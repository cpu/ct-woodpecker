package cttestsrv

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"
)

// getSTHHandler processes GET requests for the CT get-sth endpoint. It returns
// the server's current mock STH. The number of sthFetches seen by the server is
// incremented as a result of processing the request.
// TODO(@cpu): Update this comment. Conditionally return mocked STH
func (is *IntegrationSrv) getSTHHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	is.logger.Printf("%s %s request received.", is.Addr, r.URL.Path)
	start := time.Now()

	curSTHResp, err := is.GetSTH()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response, err := json.Marshal(&curSTHResp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	elapsed := time.Since(start)
	is.logger.Printf("%s %s request completed %s later", is.Addr, r.URL.Path, elapsed)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "%s", response)
}

// addChainHandler handles a HTTP POST for the add-chain and add-pre-chain CT
// endpoint.
// TODO(@cpu): Update this comment
func (is *IntegrationSrv) addChainHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}

	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var addChainReq struct {
		Chain []string
	}
	err = json.Unmarshal(bodyBytes, &addChainReq)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	precert := false
	if r.URL.Path == "/ct/v1/add-pre-chain" {
		precert = true
	}

	is.logger.Printf("%s %s request received.", is.Addr, r.URL.Path)
	start := time.Now()

	resp, err := is.AddChain(addChainReq.Chain, precert)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	respBytes, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	elapsed := time.Since(start)
	is.logger.Printf("%s %s request completed %s later", is.Addr, r.URL.Path, elapsed)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respBytes)
}

// TODO(@cpu): Comment this
func (is *IntegrationSrv) getEntriesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	startArgs, ok := r.URL.Query()["start"]
	if !ok || len(startArgs) < 1 {
		http.Error(w, "no start parameter", http.StatusBadRequest)
		return
	}
	endArgs, ok := r.URL.Query()["end"]
	if !ok || len(endArgs) < 1 {
		http.Error(w, "no end parameter", http.StatusBadRequest)
		return
	}

	start, err := strconv.ParseInt(startArgs[0], 10, 64)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	end, err := strconv.ParseInt(endArgs[0], 10, 64)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	is.logger.Printf("%s %s request received.", is.Addr, r.URL.Path)
	startTime := time.Now()

	resp, err := is.GetEntries(start, end)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	respBytes, err := json.Marshal(&resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	elapsed := time.Since(startTime)
	is.logger.Printf("%s %s request completed %s later", is.Addr, r.URL.Path, elapsed)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "%s", respBytes)
}

// TODO(@cpu): Comment this
func (is *IntegrationSrv) getConsistencyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	firstArgs, ok := r.URL.Query()["first"]
	if !ok || len(firstArgs) < 1 {
		http.Error(w, "no first parameter", http.StatusBadRequest)
		return
	}
	secondArgs, ok := r.URL.Query()["second"]
	if !ok || len(secondArgs) < 1 {
		http.Error(w, "no second parameter", http.StatusBadRequest)
		return
	}

	first, err := strconv.ParseInt(firstArgs[0], 10, 64)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	second, err := strconv.ParseInt(secondArgs[0], 10, 64)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	is.logger.Printf("%s %s request received.", is.Addr, r.URL.Path)
	start := time.Now()

	resp, err := is.GetConsistencyProof(first, second)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	respBytes, err := json.Marshal(&resp)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	elapsed := time.Since(start)
	is.logger.Printf("%s %s request completed %s later", is.Addr, r.URL.Path, elapsed)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "%s", respBytes)
}
