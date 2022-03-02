package gui

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"

	"github.com/GridPlus/phonon-client/model"
	"github.com/GridPlus/phonon-client/orchestrator"
	"github.com/GridPlus/phonon-client/session"
	"github.com/GridPlus/phonon-client/util"
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	log "github.com/sirupsen/logrus"
)

//go:embed swagger.yaml
var swaggeryaml []byte

//go:embed swagger
var swagger embed.FS

type apiSession struct {
	t orchestrator.PhononTerminal
}

func Server(port string, certFile string, keyFile string, mock bool) {
	session := apiSession{}
	if mock {
		//Start server with a mock and ignore actual cards
		err := session.t.GenerateMock()
		log.Debug("Mock generated")
		if err != nil {
			log.Error("unable to generate mock during REST server startup: ", err)
			return
		}
	} else {
		_, err := session.t.RefreshSessions()
		if err != nil {
			log.Error("unable to refresh card sessions during REST server startup: ", err)
		}
	}
	r := mux.NewRouter()

	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "HEAD", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type", "Origin"},
		AllowCredentials: true,
	})
	handler := c.Handler(r)

	// sessions
	r.HandleFunc("/genMock", session.generatemock)
	r.HandleFunc("/listSessions", session.listSessions)
	r.HandleFunc("/cards/{sessionID}/unlock", session.unlock)
	r.HandleFunc("/cards/{sessionID}/Pair", session.pair)
	// phonons
	r.HandleFunc("/cards/{sessionID}/listPhonons", session.listPhonons)
	r.HandleFunc("/cards/{sessionID}/phonon/{PhononIndex}/setDescriptor", session.setDescriptor)
	r.HandleFunc("/cards/{sessionID}/phonon/{PhononIndex}/send", session.send)
	r.HandleFunc("/cards/{sessionID}/phonon/create", session.createPhonon)
	r.HandleFunc("/cards/{sessionID}/phonon/redeem", session.redeemPhonons)
	r.HandleFunc("/cards/{sessionID}/phonon/initDeposit", session.initDepositPhonons)
	r.HandleFunc("/cards/{sessionID}/phonon/finalizeDeposit", session.finalizeDepositPhonons)
	// api docs
	r.PathPrefix("/swagger/").Handler(http.StripPrefix("/", http.FileServer(http.FS(swagger))))
	r.HandleFunc("/swagger.json", serveAPIFunc(port))

	http.Handle("/", r)
	log.Debug("Listening for incoming connections on " + port)
	if certFile != "" && keyFile != "" {
		err := http.ListenAndServeTLS(":"+port, certFile, keyFile, handler)
		if err != nil {
			log.Fatal("could not start GUI REST server on SSL: ", err)
		}
	} else {
		err := http.ListenAndServe(":"+port, handler)
		if err != nil {
			log.Fatal("could not start GUI REST server", err)
		}
	}

}

func (apiSession apiSession) createPhonon(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sess, err := apiSession.sessionFromMuxVars(vars)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	index, pubkey, err := sess.CreatePhonon()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	pub := util.ECCPubKeyToHexString(pubkey)
	enc := json.NewEncoder(w)
	enc.Encode(struct {
		Index  uint16 `json:"index"`
		PubKey string `json:"pubkey"`
	}{Index: index,
		PubKey: pub})
}

func (apiSession *apiSession) initDepositPhonons(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sess, err := apiSession.sessionFromMuxVars(vars)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	var depositPhononReq struct {
		CurrencyType  model.CurrencyType
		Denominations []int
	}
	err = json.NewDecoder(r.Body).Decode(&depositPhononReq)
	if err != nil {
		log.Error("unable to decode initDeposit request")
		return
	}
	var denoms []model.Denomination
	for _, i := range depositPhononReq.Denominations {
		d, err := model.NewDenomination(i)
		if err != nil {
			log.Error("error converting integer denomination request to denomination. err: ", err)
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
		denoms = append(denoms, d)
	}
	log.Debug("depositPhononReq: ", depositPhononReq)
	log.Debug("denoms: ", denoms)
	phonons, err := sess.InitDepositPhonons(depositPhononReq.CurrencyType, denoms)
	if err != nil {
		log.Error("unable to create phonons for deposit. err: ", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	enc := json.NewEncoder(w)
	err = enc.Encode(phonons)
	if err != nil {
		log.Error("unable to encode outgoing depositPhonons response")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (apiSession apiSession) finalizeDepositPhonons(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sess, err := apiSession.sessionFromMuxVars(vars)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}

	var depositConfirmations []session.DepositConfirmation
	err = json.NewDecoder(r.Body).Decode(&depositConfirmations)
	if err != nil {
		log.Error("unable to decode depositConfirmations json. err: ", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	ret, err := sess.FinalizeDepositPhonons(depositConfirmations)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	enc := json.NewEncoder(w)
	err = enc.Encode(ret)
	if err != nil {
		log.Error("unable to encode outgoing deposit confirmation response")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (apiSession apiSession) redeemPhonons(w http.ResponseWriter, r *http.Request) {
	sess, err := apiSession.sessionFromMuxVars(mux.Vars(r))
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	type redeemPhononRequest struct {
		P             *model.Phonon
		RedeemAddress string
	}
	var reqs []*redeemPhononRequest
	err = json.NewDecoder(r.Body).Decode(&reqs)
	if err != nil {
		log.Error("unable to decode redeemPhonons json. err: ", err)
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if len(reqs) == 0 {
		log.Error("request data empty")
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for _, req := range reqs {
		log.Debugf("received redeem phonon %+v", req.P)
		log.Debug("received redeem address: ", req.RedeemAddress)
	}
	//TODO: Validate data contains what it needs to
	type redeemPhononResp struct {
		TransactionData string
		PrivKey         string
		err             string
	}
	var resps []*redeemPhononResp
	for _, req := range reqs {
		var respErr string
		//TODO: return transaction data
		transactionData, privKeyString, err := sess.RedeemPhonon(req.P, req.RedeemAddress)
		//If err capture the error message as a string, else return string value ""
		if err != nil {
			respErr = err.Error()
		}
		resps = append(resps, &redeemPhononResp{
			TransactionData: transactionData,
			PrivKey:         privKeyString,
			err:             respErr,
		})
	}

	enc := json.NewEncoder(w)
	err = enc.Encode(resps)
	if err != nil {
		log.Error("unable to encode outgoing redeem response")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func serveapi(w http.ResponseWriter, r *http.Request) {
	http.ServeContent(w, r, "swagger.json", time.Time{}, bytes.NewReader(swaggeryaml))
}

func serveAPIFunc(port string) func(w http.ResponseWriter, r *http.Request) {
	swaggerTemplateFile := string(swaggeryaml)
	templ, err := template.New("swaggeryaml").Parse(swaggerTemplateFile)
	if err != nil {
		// this shouldn't happen. this is to make sure it fails in testing if it's set up wrong
		log.Fatal("Unable to render swagger template. Exiting")
	}
	buff := bytes.NewBuffer([]byte{})
	err = templ.Execute(buff, port)
	if err != nil {
		log.Fatal("Unable to render port into swagger yaml, Exting")
	}
	return func(w http.ResponseWriter, r *http.Request) {
		http.ServeContent(w, r, "swagger.json", time.Time{}, bytes.NewReader(buff.Bytes()))
	}
}

func (apiSession apiSession) listSessions(w http.ResponseWriter, r *http.Request) {
	sessions := apiSession.t.ListSessions()

	names := []string{}
	if len(sessions) == 0 {
		http.Error(w, "no cards found", http.StatusNotFound)
		return
	}
	for _, v := range sessions {
		names = append(names, v.GetName())
	}
	enc := json.NewEncoder(w)
	enc.Encode(struct {
		Sessions []string
	}{Sessions: names})
}

func (apiSession apiSession) unlock(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sess, err := apiSession.sessionFromMuxVars(vars)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Unable to read body", http.StatusBadRequest)
		return
	}
	unlockReq := struct {
		Pin string
	}{}
	err = json.Unmarshal(body, &unlockReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
	err = sess.VerifyPIN(unlockReq.Pin)
	if err != nil {
		http.Error(w, "Unable to validate pin", http.StatusBadRequest)
		return
	}
}

func (apiSession apiSession) pair(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sess, err := apiSession.sessionFromMuxVars(vars)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Unable to read body", http.StatusBadRequest)
		return
	}
	pairReq := struct {
		URL string `json:"url"`
	}{}
	err = json.Unmarshal(body, &pairReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	err = apiSession.t.ConnectRemoteSession(sess, pairReq.URL)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

}

type phonRet struct {
	Index  int    `json:"index"`
	PubKey string `json:"pubKey"`
	Type   int    `json:"type"`
	Value  int    `json:"value"`
}

func (apiSession apiSession) listPhonons(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sess, err := apiSession.sessionFromMuxVars(vars)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	phonons, err := sess.ListPhonons(0, 0, 0)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	for _, p := range phonons {
		p.PubKey, err = sess.GetPhononPubKey(p.KeyIndex)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	enc := json.NewEncoder(w)
	err = enc.Encode(phonons)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (apiSession apiSession) setDescriptor(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sess, err := apiSession.sessionFromMuxVars(vars)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	phononIndex, ok := vars["PhononIndex"]
	if !ok {
		http.Error(w, "Phonon not found", http.StatusNotFound)
		return
	}
	index, err := strconv.ParseUint(phononIndex, 10, 16)
	if err != nil {
		http.Error(w, "Unable to convert index to int:"+err.Error(), http.StatusBadRequest)
		return
	}
	b, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "unable to read body", http.StatusBadRequest)
		return
	}

	inputs := struct {
		CurrencyType int `json:"currencyType"`
		Value        int `json:"value"`
	}{}
	json.Unmarshal(b, &inputs)

	den, err := model.NewDenomination(inputs.Value)
	if err != nil {
		http.Error(w, "Unable to convert value to base and exponent form for phonon storage: "+err.Error(), http.StatusBadRequest)
	}

	p := &model.Phonon{
		KeyIndex:     uint16(index),
		Denomination: den,
		CurrencyType: model.CurrencyType(inputs.CurrencyType),
	}
	p.KeyIndex = uint16(index)

	err = sess.SetDescriptor(p)
	if err != nil {
		http.Error(w, "Unable to set descriptor", http.StatusBadRequest)
		return
	}
}

func (apiSession apiSession) send(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	sess, err := apiSession.sessionFromMuxVars(vars)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	phononIndex, ok := vars["PhononIndex"]
	if !ok {
		http.Error(w, "Phonon not found", http.StatusNotFound)
		return
	}
	index, err := strconv.ParseUint(phononIndex, 10, 16)
	if err != nil {
		http.Error(w, "Unable to convert index to int:"+err.Error(), http.StatusBadRequest)
		return
	}
	err = sess.SendPhonons([]uint16{uint16(index)})
	if err != nil {
		http.Error(w, "unable to send phonons: "+err.Error(), http.StatusInternalServerError)
	}
}

//TODO: Change to exportPhonon or similar description
// func (apiSession apiSession) redeemPhonon(w http.ResponseWriter, r *http.Request) {
// 	vars := mux.Vars(r)
// 	sess, err := apiSession.sessionFromMuxVars(vars)
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusNotFound)
// 		return
// 	}
// 	phononIndex, ok := vars["PhononIndex"]
// 	if !ok {
// 		http.Error(w, "Phonon not found", http.StatusNotFound)
// 		return
// 	}
// 	index, err := strconv.ParseUint(phononIndex, 10, 16)
// 	if err != nil {
// 		http.Error(w, "Unable to convert index to int:"+err.Error(), http.StatusBadRequest)
// 		return
// 	}
// 	privkey, err := sess.DestroyPhonon(uint16(index))
// 	if err != nil {
// 		http.Error(w, "Unable to redeem phonon: "+err.Error(), http.StatusInternalServerError)
// 		return
// 	}
// 	ret := struct {
// 		PrivateKey string `json:"privateKey"`
// 	}{PrivateKey: fmt.Sprintf("%x", privkey.D)}
// 	enc := json.NewEncoder(w)
// 	err = enc.Encode(ret)
// 	if err != nil {
// 		http.Error(w, err.Error(), http.StatusInternalServerError)
// 		return
// 	}
// }

func (apiSession apiSession) generatemock(w http.ResponseWriter, r *http.Request) {
	err := apiSession.t.GenerateMock()
	if err != nil {
		http.Error(w, "unable to generate mock", http.StatusInternalServerError)
	}
}

func (apiSession apiSession) sessionFromMuxVars(p map[string]string) (*session.Session, error) {
	sessionName, ok := p["sessionID"]
	if !ok {
		fmt.Println("unable to find session")
		return nil, fmt.Errorf("unable to find sesion")
	}
	sessions := apiSession.t.ListSessions()
	var targetSession *session.Session
	for _, session := range sessions {
		if session.GetName() == sessionName {
			targetSession = session
			break
		}
	}
	if targetSession == nil {
		return nil, fmt.Errorf("unable to find sesion")
	}
	return targetSession, nil
}
