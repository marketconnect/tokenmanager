package tokenmanager

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
)

// JWTManager manages JWT tokens
type JWTManager struct {
	secretKey     string
	tokenDuration time.Duration
}

type UserClaims struct {
	jwt.StandardClaims
	UserId       uint64 `json:"userId"`
	Subscription string `json:"subscription,omitempty"`
	EndDate      string `json:"endDate,omitempty"`
	ScopesMask   int    `json:"scopes"` // Поле для битовой маски scopes
}

// Constants of bit masks for scopes
const (
	ScopeTestContour        = 0x001
	ScopeContent            = 0x002
	ScopeAnalytics          = 0x004
	ScopePricesDiscounts    = 0x008
	ScopeMarketplace        = 0x010
	ScopeStatistics         = 0x020
	ScopePromotion          = 0x040
	ScopeQuestionsFeedbacks = 0x080
	ScopeChat               = 0x100
	ScopeRecommendations    = 0x200
	ScopeReadOnly           = 0x40000000
)

// NewJWTManager creates a new instance of JWTManager
func NewJWTManager(secretKey string, tokenDuration time.Duration) *JWTManager {
	return &JWTManager{secretKey, tokenDuration}
}

// GenerateWithScopes generates JWT token with scopes
func (manager *JWTManager) GenerateWithScopes(userId uint64, subscription string, endDate string, scopesMask int) (string, error) {
	claims := UserClaims{
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(manager.tokenDuration).Unix(),
		},
		UserId:       userId,
		Subscription: subscription,
		EndDate:      endDate,
		ScopesMask:   scopesMask,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(manager.secretKey))
}

// VerifyWithSubscriptionAndScopes verifies JWT and returns user ID and scopes
func (manager *JWTManager) VerifyWithSubscriptionAndScopes(accessToken string, language string) (*uint64, *string, *string, []string, error) {
	token, err := jwt.ParseWithClaims(
		accessToken,
		&UserClaims{},
		func(token *jwt.Token) (interface{}, error) {
			_, ok := token.Method.(*jwt.SigningMethodHMAC)
			if !ok {
				return nil, fmt.Errorf("unexpected token signing method")
			}
			return []byte(manager.secretKey), nil
		},
	)

	if err != nil {
		return nil, nil, nil, nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*UserClaims)
	if !ok || claims.Subscription == "" || claims.EndDate == "" {
		return nil, nil, nil, nil, fmt.Errorf("invalid token claims or missing subscription data")
	}

	// decode scopes
	scopes := DecodeScopes(claims.ScopesMask, language)

	return &claims.UserId, &claims.Subscription, &claims.EndDate, scopes, nil
}

// DecodeScopes decode a bitmask of scopes in a list of permissions
func DecodeScopes(scopesMask int, language string) []string {
	languageDictionary := map[string]map[string]string{
		"testContour":        {"ru": "Тестовый контур", "en": "Test contour"},
		"content":            {"ru": "Контент", "en": "Content"},
		"analytics":          {"ru": "Аналитика", "en": "Analytics"},
		"pricesDiscounts":    {"ru": "Цены и скидки", "en": "Prices and discounts"},
		"marketplace":        {"ru": "Маркетплейс", "en": "Marketplace"},
		"statistics":         {"ru": "Статистика", "en": "Statistics"},
		"promotion":          {"ru": "Продвижение", "en": "Promotion"},
		"questionsFeedbacks": {"ru": "Вопросы и отзывы", "en": "Questions and feedbacks"},
		"chat":               {"ru": "Чат с покупателями", "en": "Buyers chat"},
		"recommendations":    {"ru": "Рекомендации", "en": "Recommendations"},
		"tokenReadOnly":      {"ru": "Токен только на чтение", "en": "Token with read only access"},
		"tokenReadWrite":     {"ru": "Токен на чтение и запись", "en": "Token with read and write access"},
	}

	var scopes []string

	if scopesMask&ScopeTestContour == ScopeTestContour {
		scopes = append(scopes, languageDictionary["testContour"][language])
	}
	if scopesMask&ScopeContent == ScopeContent {
		scopes = append(scopes, languageDictionary["content"][language])
	}
	if scopesMask&ScopeAnalytics == ScopeAnalytics {
		scopes = append(scopes, languageDictionary["analytics"][language])
	}
	if scopesMask&ScopePricesDiscounts == ScopePricesDiscounts {
		scopes = append(scopes, languageDictionary["pricesDiscounts"][language])
	}
	if scopesMask&ScopeMarketplace == ScopeMarketplace {
		scopes = append(scopes, languageDictionary["marketplace"][language])
	}
	if scopesMask&ScopeStatistics == ScopeStatistics {
		scopes = append(scopes, languageDictionary["statistics"][language])
	}
	if scopesMask&ScopePromotion == ScopePromotion {
		scopes = append(scopes, languageDictionary["promotion"][language])
	}
	if scopesMask&ScopeQuestionsFeedbacks == ScopeQuestionsFeedbacks {
		scopes = append(scopes, languageDictionary["questionsFeedbacks"][language])
	}
	if scopesMask&ScopeChat == ScopeChat {
		scopes = append(scopes, languageDictionary["chat"][language])
	}
	if scopesMask&ScopeRecommendations == ScopeRecommendations {
		scopes = append(scopes, languageDictionary["recommendations"][language])
	}

	// add "read only" or "read and write"
	if scopesMask&ScopeReadOnly == ScopeReadOnly {
		scopes = append(scopes, languageDictionary["tokenReadOnly"][language])
	} else {
		scopes = append(scopes, languageDictionary["tokenReadWrite"][language])
	}

	return scopes
}

func EncodeScopes(scopes []string) int {
	scopeMap := map[string]int{
		"testContour":        ScopeTestContour,
		"content":            ScopeContent,
		"analytics":          ScopeAnalytics,
		"pricesDiscounts":    ScopePricesDiscounts,
		"marketplace":        ScopeMarketplace,
		"statistics":         ScopeStatistics,
		"promotion":          ScopePromotion,
		"questionsFeedbacks": ScopeQuestionsFeedbacks,
		"chat":               ScopeChat,
		"recommendations":    ScopeRecommendations,
		"tokenReadOnly":      ScopeReadOnly,
	}

	mask := 0
	for _, scope := range scopes {
		if val, exists := scopeMap[scope]; exists {
			mask |= val
		}
	}

	return mask
}
