package main

import (
	"encoding/json"
	"fmt"
	"github.com/gorilla/mux"
	"net/http"
)

func main() {
	h := &httpHandler{}

	r := mux.NewRouter()
	r.Path("/identities").Methods("GET").HandlerFunc(h.HandleListIdentities)
	r.Path("/identities/{IdentityName}").Methods("PUT").HandlerFunc(h.HandlePutIdentity)
	r.Path("/identities/{IdentityName}/roles").Methods("PUT").HandlerFunc(h.HandlePutIdentityAttachedRoles)
	r.Path("/identities/{IdentityName}").Methods("DELETE").HandlerFunc(h.HandleDeleteIdentity)

	http.Handle("/", r)
	err := http.ListenAndServe(":8080", http.DefaultServeMux)
	if err != nil {
		fmt.Printf("%+v\n", err)
		panic(err)
	}
}

type httpHandler struct {
	handler Handler
}

func (h *httpHandler) HandleListIdentities(w http.ResponseWriter, r *http.Request) {
	output, err := h.handler.ListIdentities(r.Context(), &ListIdentitiesInput{
		NextToken: r.URL.Query().Get("NextToken"),
	})
	if err != nil {
		fmt.Printf("%+v\n", err)
		panic(err)
	}

	j, _ := json.Marshal(output)
	w.Header().Set("Content-type", "application/json")
	w.Write(j)
}

func (h *httpHandler) HandlePutIdentity(w http.ResponseWriter, r *http.Request) {
	input := &PutIdentityInput{}
	err := json.NewDecoder(r.Body).Decode(&input)
	if err != nil {
		fmt.Printf("%+v\n", err)
		panic(err)
	}

	input.IdentityName = mux.Vars(r)["IdentityName"]

	output, err := h.handler.PutIdentity(r.Context(), input)
	if err != nil {
		fmt.Printf("%+v\n", err)
		panic(err)
	}

	j, _ := json.Marshal(output)
	w.Header().Set("Content-type", "application/json")
	w.Write(j)
}

func (h *httpHandler) HandlePutIdentityAttachedRoles(w http.ResponseWriter, r *http.Request) {
	input := &PutIdentityAttachedRolesInput{}
	err := json.NewDecoder(r.Body).Decode(&input)
	if err != nil {
		fmt.Printf("%+v\n", err)
		panic(err)
	}

	input.IdentityName = mux.Vars(r)["IdentityName"]

	output, err := h.handler.PutIdentityAttachedRoles(r.Context(), input)
	if err != nil {
		fmt.Printf("%+v\n", err)
		panic(err)
	}

	j, _ := json.Marshal(output)
	w.Header().Set("Content-type", "application/json")
	w.Write(j)
}

func (h *httpHandler) HandleDeleteIdentity(w http.ResponseWriter, r *http.Request) {
	output, err := h.handler.DeleteIdentity(r.Context(), &DeleteIdentityInput{
		IdentityName: mux.Vars(r)["IdentityName"],
	})
	if err != nil {
		fmt.Printf("%+v\n", err)
		panic(err)
	}

	j, _ := json.Marshal(output)
	w.Header().Set("Content-type", "application/json")
	w.Write(j)
}
