package internal

import (
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
)

// RetrieveSessionToken retrieves session token according to access token and OTP code.
func RetrieveSessionToken(otpCode string, accessKeyID string, secretAccessKey string, durationSec int64, mfaSerial string) (*sts.GetSessionTokenOutput, error) {
	sess, err := session.NewSession(&aws.Config{
		Credentials: credentials.NewStaticCredentials(accessKeyID, secretAccessKey, ""),
	})
	if err != nil {
		return nil, err
	}

	svc := sts.New(sess)
	input := &sts.GetSessionTokenInput{
		DurationSeconds: aws.Int64(durationSec),
		SerialNumber:    aws.String(mfaSerial),
		TokenCode:       aws.String(otpCode),
	}

	return svc.GetSessionToken(input)
}
