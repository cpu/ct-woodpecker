package cttestsrv

import (
	"encoding/json"
	"fmt"
	"github.com/google/certificate-transparency-go"
	"io/ioutil"
	"net/http"
)

// setSTHHandler allows setting the server's mock STH through a HTTP POST
// request.
func (is *IntegrationSrv) setSTHHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.NotFound(w, r)
		return
	}
	msg, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var mockSTH struct {
		TreeSize  uint64 `json:"tree_size"`
		Timestamp uint64
		RootHash  string `json:"sha256_root_hash"`
	}
	err = json.Unmarshal(msg, &mockSTH)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	var root ct.SHA256Hash
	err = root.FromBase64String(mockSTH.RootHash)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	sth := &ct.SignedTreeHead{
		TreeSize:       mockSTH.TreeSize,
		Timestamp:      mockSTH.Timestamp,
		SHA256RootHash: root,
	}
	is.SetSTH(sth)
	w.WriteHeader(http.StatusOK)
}

func (is *IntegrationSrv) clearSTHHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	is.SetSTH(nil)
	w.WriteHeader(http.StatusOK)
}

// integrateHandler accepts GET requests indicating the testLog should sequence
// a batch of unintegrated leaves that have been submitted through the add
// chains endpoint. The number of sequenced leaves is returned as the HTTP
// response body.
func (is *IntegrationSrv) integrateHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	count, err := is.Integrate()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	is.logger.Printf("%s %s request received.", is.Addr, r.URL.Path)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "%d", count)
	is.logger.Printf("%s %s request completed.", is.Addr, r.URL.Path)
}

// getSubmissions handler allows fetching the number of add-chain/add-pre-chain
// requests processed so far using an HTTP GET request.
func (is *IntegrationSrv) getSubmissionsHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	is.logger.Printf("%s %s request received.", is.Addr, r.URL.Path)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "%d", is.Submissions())
	is.logger.Printf("%s %s request completed.", is.Addr, r.URL.Path)
}

// getSTHFetchesHandler allows fetching the number of get-sth requests processed
// by the server so far by sending a HTTP GET request.
func (is *IntegrationSrv) getSTHFetchesHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.NotFound(w, r)
		return
	}

	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "%d", is.STHFetches())
}
