package eventsub_framework

import (
	"context"
	"encoding/json"
	"io"
	"net/http"

	"github.com/mozillazg/go-httpheader"
	"github.com/twirapp/twitch-eventsub-framework/esb"
)

const (
	webhookCallbackVerification = "webhook_callback_verification"
	notificationMessageType     = "notification"
	revocationMessageType       = "revocation"
)

// SubHandler implements http.Handler to receive Twitch webhook notifications.
//
// SubHandler handles both verification of new subscriptions and dispatching of
// event notifications. To handle a specific event, set the corresponding
// HandleXXX struct field. When a notification is received and validated, the
// handler function will be invoked in a new goroutine.
type SubHandler struct {
	doSignatureVerification bool
	signatureSecret         []byte

	// Challenge handler function.
	// Returns whether the subscription should be accepted.
	VerifyChallenge func(ctx context.Context, h *esb.ResponseHeaders, chal *esb.SubscriptionChallenge) bool
	OnRevocate      func(ctx context.Context, h *esb.ResponseHeaders, revocation *esb.RevocationNotification)
	OnNotification  func(ctx context.Context, h *esb.ResponseHeaders, notification *esb.EventNotification)

	// IDTracker used to deduplicate notifications
	IDTracker               IDTracker
	OnDuplicateNotification func(ctx context.Context, h *esb.ResponseHeaders)

	HandleChannelUpdate func(ctx context.Context, h *esb.ResponseHeaders, event *esb.EventChannelUpdate)
	HandleChannelFollow func(ctx context.Context, h *esb.ResponseHeaders, event *esb.EventChannelFollow)
	HandleUserUpdate    func(ctx context.Context, h *esb.ResponseHeaders, event *esb.EventUserUpdate)

	HandleChannelSubscribe       func(ctx context.Context, h *esb.ResponseHeaders, event *esb.EventChannelSubscribe)
	HandleChannelSubscriptionEnd func(
		ctx context.Context,
		h *esb.ResponseHeaders,
		event *esb.EventChannelSubscriptionEnd,
	)
	HandleChannelSubscriptionGift func(
		ctx context.Context,
		h *esb.ResponseHeaders,
		event *esb.EventChannelSubscriptionGift,
	)
	HandleChannelSubscriptionMessage func(
		ctx context.Context,
		h *esb.ResponseHeaders,
		event *esb.EventChannelSubscriptionMessage,
	)
	HandleChannelCheer func(ctx context.Context, h *esb.ResponseHeaders, event *esb.EventChannelCheer)
	HandleChannelRaid  func(ctx context.Context, h *esb.ResponseHeaders, event *esb.EventChannelRaid)

	HandleChannelBan             func(ctx context.Context, h *esb.ResponseHeaders, event *esb.EventChannelBan)
	HandleChannelUnban           func(ctx context.Context, h *esb.ResponseHeaders, event *esb.EventChannelUnban)
	HandleChannelModeratorAdd    func(ctx context.Context, h *esb.ResponseHeaders, event *esb.EventChannelModeratorAdd)
	HandleChannelModeratorRemove func(ctx context.Context, h *esb.ResponseHeaders, event *esb.EventChannelModeratorRemove)

	HandleChannelPointsRewardAdd func(
		ctx context.Context,
		h *esb.ResponseHeaders,
		event *esb.EventChannelPointsRewardAdd,
	)
	HandleChannelPointsRewardUpdate func(
		ctx context.Context,
		h *esb.ResponseHeaders,
		event *esb.EventChannelPointsRewardUpdate,
	)
	HandleChannelPointsRewardRemove func(
		ctx context.Context,
		h *esb.ResponseHeaders,
		event *esb.EventChannelPointsRewardRemove,
	)
	HandleChannelPointsRewardRedemptionAdd func(
		ctx context.Context,
		h *esb.ResponseHeaders,
		event *esb.EventChannelPointsRewardRedemptionAdd,
	)
	HandleChannelPointsRewardRedemptionUpdate func(
		ctx context.Context,
		h *esb.ResponseHeaders,
		event *esb.EventChannelPointsRewardRedemptionUpdate,
	)

	HandleChannelPollBegin    func(ctx context.Context, h *esb.ResponseHeaders, event *esb.EventChannelPollBegin)
	HandleChannelPollProgress func(ctx context.Context, h *esb.ResponseHeaders, event *esb.EventChannelPollProgress)
	HandleChannelPollEnd      func(ctx context.Context, h *esb.ResponseHeaders, event *esb.EventChannelPollEnd)

	HandleChannelPredictionBegin func(
		ctx context.Context,
		h *esb.ResponseHeaders,
		event *esb.EventChannelPredictionBegin,
	)
	HandleChannelPredictionProgress func(
		ctx context.Context,
		h *esb.ResponseHeaders,
		event *esb.EventChannelPredictionProgress,
	)
	HandleChannelPredictionLock func(
		ctx context.Context,
		h *esb.ResponseHeaders,
		event *esb.EventChannelPredictionLock,
	)
	HandleChannelPredictionEnd func(ctx context.Context, h *esb.ResponseHeaders, event *esb.EventChannelPredictionEnd)

	HandleDropEntitlementGrant func(
		ctx context.Context,
		h *esb.ResponseHeaders,
		event *esb.EventDropEntitlementGrant,
	)
	HandleExtensionBitsTransactionCreate func(
		ctx context.Context,
		h *esb.ResponseHeaders,
		event *esb.EventBitsTransactionCreate,
	)

	HandleGoalBegin    func(ctx context.Context, h *esb.ResponseHeaders, event *esb.EventGoals)
	HandleGoalProgress func(ctx context.Context, h *esb.ResponseHeaders, event *esb.EventGoals)
	HandleGoalEnd      func(ctx context.Context, h *esb.ResponseHeaders, event *esb.EventGoals)

	HandleHypeTrainBegin    func(ctx context.Context, h *esb.ResponseHeaders, event *esb.EventHypeTrainBegin)
	HandleHypeTrainProgress func(ctx context.Context, h *esb.ResponseHeaders, event *esb.EventHypeTrainProgress)
	HandleHypeTrainEnd      func(ctx context.Context, h *esb.ResponseHeaders, event *esb.EventHypeTrainEnd)

	HandleStreamOnline  func(ctx context.Context, h *esb.ResponseHeaders, event *esb.EventStreamOnline)
	HandleStreamOffline func(ctx context.Context, h *esb.ResponseHeaders, event *esb.EventStreamOffline)

	HandleUserAuthorizationGrant  func(ctx context.Context, h *esb.ResponseHeaders, event *esb.EventUserAuthorizationGrant)
	HandleUserAuthorizationRevoke func(
		ctx context.Context,
		h *esb.ResponseHeaders,
		event *esb.EventUserAuthorizationRevoke,
	)

	HandleChannelChatMessage           func(ctx context.Context, h *esb.ResponseHeaders, event *esb.EventChannelChatMessage)
	HandleChannelChatClear             func(ctx context.Context, h *esb.ResponseHeaders, event *esb.EventChannelChatClear)
	HandleChannelChatClearUserMessages func(
		ctx context.Context,
		h *esb.ResponseHeaders,
		event *esb.EventChannelChatClearUserMessages,
	)
	HandleChannelChatMessageDelete func(
		ctx context.Context,
		h *esb.ResponseHeaders,
		event *esb.EventChannelChatMessageDelete,
	)

	HandleChannelChatNotification func(
		ctx context.Context,
		h *esb.ResponseHeaders,
		event *esb.EventChannelChatNotification,
	)

	HandleChannelUnbanRequestCreate func(
		ctx context.Context,
		h *esb.ResponseHeaders,
		event *esb.ChannelUnbanRequestCreate,
	)

	HandleChannelUnbanRequestResolve func(
		ctx context.Context,
		h *esb.ResponseHeaders,
		event *esb.ChannelUnbanRequestResolve,
	)

	HandleChannelVipAdd    func(ctx context.Context, h *esb.ResponseHeaders, event *esb.ChannelVipAdd)
	HandleChannelVipRemove func(ctx context.Context, h *esb.ResponseHeaders, event *esb.ChannelVipRemove)
}

func NewSubHandler(doSignatureVerification bool, secret []byte) *SubHandler {
	if doSignatureVerification && secret == nil {
		panic("secret must be set if signature verification is enabled")
	}

	return &SubHandler{
		doSignatureVerification: doSignatureVerification,
		signatureSecret:         secret,
	}
}

func (s *SubHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		s.handlePost(w, r)
	} else {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (s *SubHandler) handlePost(w http.ResponseWriter, r *http.Request) {
	// Read body into buffer
	defer r.Body.Close()
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if s.doSignatureVerification {
		if valid, err := VerifyRequestSignature(r, bodyBytes, s.signatureSecret); err != nil || !valid {
			http.Error(w, "Invalid request signature", http.StatusForbidden)
			return
		}
	}

	// Decode request headers to verify and dispatch payload
	var h esb.ResponseHeaders
	if err := httpheader.Decode(r.Header, &h); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	isDuplicate, err := s.checkIfDuplicate(w, r, &h)
	if err != nil {
		// Error occurred while checking IDTracker
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	} else if isDuplicate {
		return // already handled response
	}

	switch h.MessageType {
	case webhookCallbackVerification:
		s.handleVerification(w, bodyBytes, &h)
		return
	case notificationMessageType:
		s.handleNotification(r.Context(), w, bodyBytes, &h)
		return
	case revocationMessageType:
		s.handleRevocation(r.Context(), w, bodyBytes, &h)
	default:
		http.Error(w, "Unknown message type", http.StatusBadRequest)
		return
	}
}

// checkIfDuplicate returns whether the IDTracker reports this notification is
// a duplicate. If it is a duplicate, it writes a 2xx response and returns true.
// Otherwise, it returns false.
func (s *SubHandler) checkIfDuplicate(
	w http.ResponseWriter,
	r *http.Request,
	h *esb.ResponseHeaders,
) (bool, error) {
	if s.IDTracker != nil {
		duplicate, err := s.IDTracker.AddAndCheckIfDuplicate(r.Context(), h.MessageID)
		if err != nil {
			return false, err
		}

		if duplicate {
			if s.OnDuplicateNotification != nil {
				go s.OnDuplicateNotification(r.Context(), h)
			}
			writeEmptyOK(w) // ignore and return 2XX code
			return true, nil
		}
	}

	return false, nil
}

func (s *SubHandler) handleVerification(
	w http.ResponseWriter,
	bodyBytes []byte,
	headers *esb.ResponseHeaders,
) {
	var data esb.SubscriptionChallenge
	if err := json.Unmarshal(bodyBytes, &data); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	if s.VerifyChallenge == nil || s.VerifyChallenge(context.TODO(), headers, &data) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(data.Challenge))
	} else {
		http.Error(w, "Invalid subscription", http.StatusBadRequest)
	}
}

func (s *SubHandler) handleRevocation(
	ctx context.Context,
	w http.ResponseWriter,
	bodyBytes []byte,
	headers *esb.ResponseHeaders,
) {
	var data esb.RevocationNotification
	if err := json.Unmarshal(bodyBytes, &data); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	if s.OnRevocate != nil {
		s.OnRevocate(ctx, headers, &data)
	}

	writeEmptyOK(w)
}

func (s *SubHandler) handleNotification(
	ctx context.Context,
	w http.ResponseWriter,
	bodyBytes []byte,
	h *esb.ResponseHeaders,
) {
	var notification esb.EventNotification
	if err := json.Unmarshal(bodyBytes, &notification); err != nil {
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}
	event := notification.Event
	if s.OnNotification != nil {
		s.OnNotification(ctx, h, &notification)
	}

	switch h.SubscriptionType {
	case "channel.update":
		var data esb.EventChannelUpdate
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleChannelUpdate != nil {
			go s.HandleChannelUpdate(ctx, h, &data)
		}
	case "channel.follow":
		var data esb.EventChannelFollow
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleChannelFollow != nil {
			go s.HandleChannelFollow(ctx, h, &data)
		}
	case "channel.subscribe":
		var data esb.EventChannelSubscribe
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleChannelSubscribe != nil {
			go s.HandleChannelSubscribe(ctx, h, &data)
		}
	case "channel.subscription.end":
		var data esb.EventChannelSubscriptionEnd
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleChannelSubscriptionEnd != nil {
			go s.HandleChannelSubscriptionEnd(ctx, h, &data)
		}
	case "channel.subscription.gift":
		var data esb.EventChannelSubscriptionGift
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleChannelSubscriptionGift != nil {
			go s.HandleChannelSubscriptionGift(ctx, h, &data)
		}
	case "channel.subscription.message":
		var data esb.EventChannelSubscriptionMessage
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleChannelSubscriptionMessage != nil {
			go s.HandleChannelSubscriptionMessage(ctx, h, &data)
		}
	case "channel.cheer":
		var data esb.EventChannelCheer
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleChannelCheer != nil {
			go s.HandleChannelCheer(ctx, h, &data)
		}
	case "channel.raid":
		var data esb.EventChannelRaid
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleChannelRaid != nil {
			go s.HandleChannelRaid(ctx, h, &data)
		}
	case "channel.ban":
		var data esb.EventChannelBan
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleChannelBan != nil {
			go s.HandleChannelBan(ctx, h, &data)
		}
	case "channel.unban":
		var data esb.EventChannelUnban
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleChannelUnban != nil {
			go s.HandleChannelUnban(ctx, h, &data)
		}
	case "channel.moderator.add":
		var data esb.EventChannelModeratorAdd
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleChannelModeratorAdd != nil {
			go s.HandleChannelModeratorAdd(ctx, h, &data)
		}
	case "channel.moderator.remove":
		var data esb.EventChannelModeratorRemove
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleChannelModeratorRemove != nil {
			go s.HandleChannelModeratorRemove(ctx, h, &data)
		}
	case "channel.channel_points_custom_reward.add":
		var data esb.EventChannelPointsRewardAdd
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleChannelPointsRewardAdd != nil {
			go s.HandleChannelPointsRewardAdd(ctx, h, &data)
		}
	case "channel.channel_points_custom_reward.update":
		var data esb.EventChannelPointsRewardUpdate
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleChannelPointsRewardUpdate != nil {
			go s.HandleChannelPointsRewardUpdate(ctx, h, &data)
		}
	case "channel.channel_points_custom_reward.remove":
		var data esb.EventChannelPointsRewardRemove
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleChannelPointsRewardRemove != nil {
			go s.HandleChannelPointsRewardRemove(ctx, h, &data)
		}
	case "channel.channel_points_custom_reward_redemption.add":
		var data esb.EventChannelPointsRewardRedemptionAdd
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleChannelPointsRewardRedemptionAdd != nil {
			go s.HandleChannelPointsRewardRedemptionAdd(ctx, h, &data)
		}
	case "channel.channel_points_custom_reward_redemption.update":
		var data esb.EventChannelPointsRewardRedemptionUpdate
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleChannelPointsRewardRedemptionUpdate != nil {
			go s.HandleChannelPointsRewardRedemptionUpdate(ctx, h, &data)
		}
	case "channel.poll.begin":
		var data esb.EventChannelPollBegin
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleChannelPollBegin != nil {
			go s.HandleChannelPollBegin(ctx, h, &data)
		}
	case "channel.poll.progress":
		var data esb.EventChannelPollProgress
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleChannelPollProgress != nil {
			go s.HandleChannelPollProgress(ctx, h, &data)
		}
	case "channel.poll.end":
		var data esb.EventChannelPollEnd
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleChannelPollEnd != nil {
			go s.HandleChannelPollEnd(ctx, h, &data)
		}
	case "channel.prediction.begin":
		var data esb.EventChannelPredictionBegin
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleChannelPredictionBegin != nil {
			go s.HandleChannelPredictionBegin(ctx, h, &data)
		}
	case "channel.prediction.progress":
		var data esb.EventChannelPredictionProgress
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleChannelPredictionProgress != nil {
			go s.HandleChannelPredictionProgress(ctx, h, &data)
		}
	case "channel.prediction.lock":
		var data esb.EventChannelPredictionLock
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleChannelPredictionLock != nil {
			go s.HandleChannelPredictionLock(ctx, h, &data)
		}
	case "channel.prediction.end":
		var data esb.EventChannelPredictionEnd
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleChannelPredictionEnd != nil {
			go s.HandleChannelPredictionEnd(ctx, h, &data)
		}
	case "drop.entitlement.grant":
		var data esb.EventDropEntitlementGrant
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleDropEntitlementGrant != nil {
			go s.HandleDropEntitlementGrant(ctx, h, &data)
		}
	case "extension.bits_transaction.create":
		var data esb.EventBitsTransactionCreate
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleExtensionBitsTransactionCreate != nil {
			go s.HandleExtensionBitsTransactionCreate(ctx, h, &data)
		}
	case "channel.goal.begin":
		var data esb.EventGoals
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleGoalBegin != nil {
			go s.HandleGoalBegin(ctx, h, &data)
		}
	case "channel.goal.progress":
		var data esb.EventGoals
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleGoalProgress != nil {
			go s.HandleGoalProgress(ctx, h, &data)
		}
	case "channel.goal.end":
		var data esb.EventGoals
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleGoalEnd != nil {
			go s.HandleGoalEnd(ctx, h, &data)
		}
	case "channel.hype_train.begin":
		var data esb.EventHypeTrainBegin
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleHypeTrainBegin != nil {
			go s.HandleHypeTrainBegin(ctx, h, &data)
		}
	case "channel.hype_train.progress":
		var data esb.EventHypeTrainProgress
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleHypeTrainProgress != nil {
			go s.HandleHypeTrainProgress(ctx, h, &data)
		}
	case "channel.hype_train.end":
		var data esb.EventHypeTrainEnd
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleHypeTrainEnd != nil {
			go s.HandleHypeTrainEnd(ctx, h, &data)
		}
	case "stream.online":
		var data esb.EventStreamOnline
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleStreamOnline != nil {
			go s.HandleStreamOnline(ctx, h, &data)
		}
	case "stream.offline":
		var data esb.EventStreamOffline
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleStreamOffline != nil {
			go s.HandleStreamOffline(ctx, h, &data)
		}
	case "user.authorization.grant":
		var data esb.EventUserAuthorizationGrant
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleUserAuthorizationGrant != nil {
			go s.HandleUserAuthorizationGrant(ctx, h, &data)
		}
	case "user.authorization.revoke":
		var data esb.EventUserAuthorizationRevoke
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleUserAuthorizationRevoke != nil {
			go s.HandleUserAuthorizationRevoke(ctx, h, &data)
		}
	case "user.update":
		var data esb.EventUserUpdate
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleUserUpdate != nil {
			go s.HandleUserUpdate(ctx, h, &data)
		}
	case "channel.chat.message":
		var data esb.EventChannelChatMessage
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleChannelChatMessage != nil {
			go s.HandleChannelChatMessage(ctx, h, &data)
		}
	case "channel.chat.clear":
		var data esb.EventChannelChatClear
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleChannelChatClear != nil {
			go s.HandleChannelChatClear(ctx, h, &data)
		}
	case "channel.chat.clear_user_messages":
		var data esb.EventChannelChatClearUserMessages
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleChannelChatClearUserMessages != nil {
			go s.HandleChannelChatClearUserMessages(ctx, h, &data)
		}
	case "channel.chat.message_delete":
		var data esb.EventChannelChatMessageDelete
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleChannelChatMessageDelete != nil {
			go s.HandleChannelChatMessageDelete(ctx, h, &data)
		}
	case "channel.chat.notification":
		var data esb.EventChannelChatNotification
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleChannelChatNotification != nil {
			go s.HandleChannelChatNotification(ctx, h, &data)
		}
	case "channel.unban_request.create":
		var data esb.ChannelUnbanRequestCreate
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleChannelUnbanRequestCreate != nil {
			go s.HandleChannelUnbanRequestCreate(ctx, h, &data)
		}
	case "channel.unban_request.resolve":
		var data esb.ChannelUnbanRequestResolve
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleChannelUnbanRequestResolve != nil {
			go s.HandleChannelUnbanRequestResolve(ctx, h, &data)
		}

	case "channel.vip.add":
		var data esb.ChannelVipAdd
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleChannelVipAdd != nil {
			go s.HandleChannelVipAdd(ctx, h, &data)
		}
	case "channel.vip.remove":
		var data esb.ChannelVipRemove
		if err := json.Unmarshal(event, &data); err != nil {
			http.Error(w, "Invalid JSON body", http.StatusBadRequest)
			return
		}
		if s.HandleChannelVipRemove != nil {
			go s.HandleChannelVipRemove(ctx, h, &data)
		}
	default:
		http.Error(w, "Unknown notification type", http.StatusBadRequest)
		return
	}

	writeEmptyOK(w)
}

// Writes a 200 OK response
func writeEmptyOK(w http.ResponseWriter) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}
