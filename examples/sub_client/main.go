package main

import (
	"context"
	"fmt"

	esf "github.com/twirapp/twitch-eventsub-framework"
	"github.com/twirapp/twitch-eventsub-framework/esb"
)

const (
	// These are usually created by your application automatically
	clientID = `abc123`
	appToken = `def456`
	// Key for verifying webhook requests
	secretKey = `hey this is really secret`
)

func main() {
	client := esf.NewSubClient(esf.NewStaticCredentials(clientID, appToken))
	res, _ := client.Subscribe(context.Background(), &esf.SubRequest{
		Type: "channel.update",
		Condition: esb.ConditionChannelUpdate{
			BroadcasterUserID: "22484632",
		},
		Callback: "https://my.website/api/twitch/webhooks",
		Secret:   secretKey,
	})

	fmt.Printf("Using %d/%d of webhook cost limit\n", res.TotalCost, res.MaxTotalCost)
}
