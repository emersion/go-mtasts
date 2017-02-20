package mtasts_test

import (
	"log"

	"github.com/emersion/go-mtasts"
)

func ExampleFetch() {
	policy, err := mtasts.Fetch("gmail.com")
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("%+v\n", policy)
}
