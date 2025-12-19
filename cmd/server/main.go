package main

import "log"

func main() {
	if err := run(); err != nil {
		log.Fatalf("Application error: %v", err)
	}
}
