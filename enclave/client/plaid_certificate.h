#pragma once

// 1. Plaid: (sandbox.plaid.com, development.plaid.com) (Expires Aug 5 2022)
// 2. Plaid: (production.plaid.com) (Expires Jun 23 2022)

#define plaid_certificate \
"-----BEGIN CERTIFICATE-----\r\n"\
"MIIHlDCCBnygAwIBAgIQC7+ssUSKfkQiWea5yTfytjANBgkqhkiG9w0BAQsFADB1\r\n"\
"MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\r\n"\
"d3cuZGlnaWNlcnQuY29tMTQwMgYDVQQDEytEaWdpQ2VydCBTSEEyIEV4dGVuZGVk\r\n"\
"IFZhbGlkYXRpb24gU2VydmVyIENBMB4XDTIwMDcwMTAwMDAwMFoXDTIyMDgwNTEy\r\n"\
"MDAwMFowgd4xHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRMwEQYLKwYB\r\n"\
"BAGCNzwCAQMTAlVTMRkwFwYLKwYBBAGCNzwCAQITCERlbGF3YXJlMRAwDgYDVQQF\r\n"\
"Ewc1MTg1MTY4MQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQG\r\n"\
"A1UEBxMNU2FuIEZyYW5jaXNjbzESMBAGA1UEChMJUGxhaWQgSW5jMREwDwYDVQQL\r\n"\
"EwhTZWN1cml0eTEaMBgGA1UEAxMRc2FuZGJveC5wbGFpZC5jb20wggEiMA0GCSqG\r\n"\
"SIb3DQEBAQUAA4IBDwAwggEKAoIBAQC2S0pTH6Ii5bqyzNwOY1ueNvPSg/cem85k\r\n"\
"vIkTQYQNcL1irMhtrnvdGo2zRoUUdAhkSXQQDDkXBewlP8rL5FrAwWWX36Jc382m\r\n"\
"hxPnRQF/gTyT/vDNc9b4k3QAa1wAWtzlJlwF9WlEcqyWysv8S71pVVgGHcntU/iJ\r\n"\
"9Ke80baf636Hpg/54sqbebMBo2b3urcUQSiDQ6js5wPASR5cnxhgN5N4rEoFg2Ph\r\n"\
"pv8GQ7isKozqdJVBelwOjOCYd16x8g0RaEodNm16JN1xMS7Es7tCanTZoRjtq/SD\r\n"\
"TL+py3tS/2n8h9sD1eACBXalsBlRNcHqkUENRzC5mABlRggK2rR9AgMBAAGjggO0\r\n"\
"MIIDsDAfBgNVHSMEGDAWgBQ901Cl1qCt7vNKYApl0yHU+PjWDzAdBgNVHQ4EFgQU\r\n"\
"eixe+ex353i5gysFtvPWyfz1nN8wXwYDVR0RBFgwVoIRc2FuZGJveC5wbGFpZC5j\r\n"\
"b22CFWRldmVsb3BtZW50LnBsYWlkLmNvbYISc2FuZGJveDIucGxhaWQuY29tghZk\r\n"\
"ZXZlbG9wbWVudDIucGxhaWQuY29tMA4GA1UdDwEB/wQEAwIFoDAdBgNVHSUEFjAU\r\n"\
"BggrBgEFBQcDAQYIKwYBBQUHAwIwdQYDVR0fBG4wbDA0oDKgMIYuaHR0cDovL2Ny\r\n"\
"bDMuZGlnaWNlcnQuY29tL3NoYTItZXYtc2VydmVyLWcyLmNybDA0oDKgMIYuaHR0\r\n"\
"cDovL2NybDQuZGlnaWNlcnQuY29tL3NoYTItZXYtc2VydmVyLWcyLmNybDBLBgNV\r\n"\
"HSAERDBCMDcGCWCGSAGG/WwCATAqMCgGCCsGAQUFBwIBFhxodHRwczovL3d3dy5k\r\n"\
"aWdpY2VydC5jb20vQ1BTMAcGBWeBDAEBMIGIBggrBgEFBQcBAQR8MHowJAYIKwYB\r\n"\
"BQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNvbTBSBggrBgEFBQcwAoZGaHR0\r\n"\
"cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0U0hBMkV4dGVuZGVkVmFs\r\n"\
"aWRhdGlvblNlcnZlckNBLmNydDAMBgNVHRMBAf8EAjAAMIIBfwYKKwYBBAHWeQIE\r\n"\
"AgSCAW8EggFrAWkAdwApeb7wnjk5IfBWc59jpXflvld9nGAK+PlNXSZcJV3HhAAA\r\n"\
"AXMLPh1ZAAAEAwBIMEYCIQC2y4u9+COxci9aCYZuiEkytQn7wimAoP/s7ywctzFM\r\n"\
"/wIhAPtPFEqUQszyKicAYwfsiDo3knnJNs0nWjh+xlRewQh5AHYAIkVFB1lVJFaW\r\n"\
"P6Ev8fdthuAjJmOtwEt/XcaDXG7iDwIAAAFzCz4dhwAABAMARzBFAiAszVEcGslP\r\n"\
"0tTDlkB4GpeiAjjrdS8LJV8aNLBWlT6L7wIhALvgCn1sVGdK6Woaa0ltxV2AYsaq\r\n"\
"iQIGekYnI2UhBVCPAHYAQcjKsd8iRkoQxqE6CUKHXk4xixsD6+tLx2jwkGKWBvYA\r\n"\
"AAFzCz4dIAAABAMARzBFAiEA8Ad52bWkljZLjtis9F3NJvmkDNOcLBUtckDaQgqH\r\n"\
"93QCIE7gpDdbT9ZiS3nCks0ZRY1il6A/cHM6aswrmlU0qJN5MA0GCSqGSIb3DQEB\r\n"\
"CwUAA4IBAQB/Qg1TYLIEPj5rjMQ82Ff0/VcDDGdfrQZF+yNGdaHUhsrtsHS5wlAB\r\n"\
"OeJXHwX243nCD3dFy72uOuKGvLMQKd1c8Wx/NFImL3JSP6XlOU593DqHcGniCpOe\r\n"\
"en0gHNHpZN6zlOh1D8uk0d2KeprlHVR5CsgrvHBf//cCZuxlVDF6sKX3cdmWUz/X\r\n"\
"RfezW9JMmcA0hCVx7L4hAGRypXnIzIx4TdAO2CZ0hdiCBOB1uiiB8IVGBcMCM9hR\r\n"\
"nleW63ZPqnq1TxvqTxWP/8Owpo30qbp3NX8SRVjhzJ8ZLawZu89kzstrseWulAsI\r\n"\
"v9mQGmIZ4lztXeJX49tcbj7JRcyTVgym\r\n"\
"-----END CERTIFICATE-----\r\n"\
"\r\n"\
"-----BEGIN CERTIFICATE-----\r\n"\
"MIIHbjCCBlagAwIBAgIQCRik5JYN9VbkUal36bXzPjANBgkqhkiG9w0BAQsFADB1\r\n"\
"MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\r\n"\
"d3cuZGlnaWNlcnQuY29tMTQwMgYDVQQDEytEaWdpQ2VydCBTSEEyIEV4dGVuZGVk\r\n"\
"IFZhbGlkYXRpb24gU2VydmVyIENBMB4XDTIwMDQxNjAwMDAwMFoXDTIyMDYyMzEy\r\n"\
"MDAwMFowgeExHTAbBgNVBA8MFFByaXZhdGUgT3JnYW5pemF0aW9uMRMwEQYLKwYB\r\n"\
"BAGCNzwCAQMTAlVTMRkwFwYLKwYBBAGCNzwCAQITCERlbGF3YXJlMRAwDgYDVQQF\r\n"\
"Ewc1MTg1MTY4MQswCQYDVQQGEwJVUzETMBEGA1UECBMKQ2FsaWZvcm5pYTEWMBQG\r\n"\
"A1UEBxMNU2FuIEZyYW5jaXNjbzESMBAGA1UEChMJUGxhaWQgSW5jMREwDwYDVQQL\r\n"\
"EwhTZWN1cml0eTEdMBsGA1UEAxMUcHJvZHVjdGlvbi5wbGFpZC5jb20wggEiMA0G\r\n"\
"CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC8tb6fkJdlyxOMVooTGIQL+rkdmWvt\r\n"\
"veEdMilPGwSVKuvEBCuqPBFuNWW15bFU0RKsuuoXeBaeH33ri39VpNVEsGtvAPBn\r\n"\
"wUNEb4wbmzag1rMLdUm2z0LlJpo/7UX4DGK5ntZVGEk0dfkfohF4jXsZM+WYVuLL\r\n"\
"mxLWRmXlRZ3LZ/SLiF948gcsFC2aS2PS5f0w4sGWztfr4pyBBDDfNPRKCuyHxQXR\r\n"\
"C0O63GJQ72ZFzfW7cJgl2q02Zgh4VGRZ5ns9EsnYbBW8LphW82ZPw1VfV8ENzUj5\r\n"\
"DfMul/+xtQafoQ93mM0VtLPFFmuWQpJRm5spQqcjgT76JjMoVBf3ShTBAgMBAAGj\r\n"\
"ggOLMIIDhzAfBgNVHSMEGDAWgBQ901Cl1qCt7vNKYApl0yHU+PjWDzAdBgNVHQ4E\r\n"\
"FgQU0nQIGM1Zaqyf3aqyPqV5CgRkeRowNgYDVR0RBC8wLYIUcHJvZHVjdGlvbi5w\r\n"\
"bGFpZC5jb22CFXByb2R1Y3Rpb24yLnBsYWlkLmNvbTAOBgNVHQ8BAf8EBAMCBaAw\r\n"\
"HQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMHUGA1UdHwRuMGwwNKAyoDCG\r\n"\
"Lmh0dHA6Ly9jcmwzLmRpZ2ljZXJ0LmNvbS9zaGEyLWV2LXNlcnZlci1nMi5jcmww\r\n"\
"NKAyoDCGLmh0dHA6Ly9jcmw0LmRpZ2ljZXJ0LmNvbS9zaGEyLWV2LXNlcnZlci1n\r\n"\
"Mi5jcmwwSwYDVR0gBEQwQjA3BglghkgBhv1sAgEwKjAoBggrBgEFBQcCARYcaHR0\r\n"\
"cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQUzAHBgVngQwBATCBiAYIKwYBBQUHAQEE\r\n"\
"fDB6MCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2VydC5jb20wUgYIKwYB\r\n"\
"BQUHMAKGRmh0dHA6Ly9jYWNlcnRzLmRpZ2ljZXJ0LmNvbS9EaWdpQ2VydFNIQTJF\r\n"\
"eHRlbmRlZFZhbGlkYXRpb25TZXJ2ZXJDQS5jcnQwDAYDVR0TAQH/BAIwADCCAX8G\r\n"\
"CisGAQQB1nkCBAIEggFvBIIBawFpAHcAKXm+8J45OSHwVnOfY6V35b5XfZxgCvj5\r\n"\
"TV0mXCVdx4QAAAFxgIdJbAAABAMASDBGAiEAsPEsIQ+qotL7KOxjm+6IqYMl0+ua\r\n"\
"+WzghqORHxnUB/UCIQDIMjlCoryphk3fU8TIxNvGOOejOMCYSXhsPVnxNVi7qQB2\r\n"\
"ACJFRQdZVSRWlj+hL/H3bYbgIyZjrcBLf13Gg1xu4g8CAAABcYCHSgsAAAQDAEcw\r\n"\
"RQIgFGiM140xBgWJPX+wJbqiWeTkAcigGj0kPgpvqBxmx74CIQDAbh23QFaGDHj6\r\n"\
"DzGgscPsf8DgczI5hVRsW2e68tzpxgB2AEHIyrHfIkZKEMahOglCh15OMYsbA+vr\r\n"\
"S8do8JBilgb2AAABcYCHSSoAAAQDAEcwRQIhAIrtFmj7x8WqpaQZMaEbZ7ZW7ulr\r\n"\
"KaQDxv5vzgCoiNuwAiBSzslwbgkuXtzn0WiEB5H1wnHyRivJI+fg8Uxaj9NPPDAN\r\n"\
"BgkqhkiG9w0BAQsFAAOCAQEARE4hnoYEsyQlVP4oFjTBrRAu7LLN6ggy0VfTZhg7\r\n"\
"Cim0dc+aM4J946Tnp8luAS+kBM4vBvNNWkDwFo7YzlfSdn3msj666krCHJIN8VKt\r\n"\
"6rLSrzf3YuqKRPrum7TDY6Xp3uOS2X0g3C4HB8L6IdVxvUDPCiga7gp7j6aAox/M\r\n"\
"zRaV+oJDs4xktwwWmXq1lvTiFX1LQdw+SVdRw87BtAkE6jVfaIUqg/OhgaaXOU7v\r\n"\
"xP9Y9Gp0DZAVwSsXzG6M/+K0y+fPYMhFZzJnLwZ7md9TUtC105MQu/fujUBIXrPR\r\n"\
"UueUc0PESWX7UEfUMDova2DUJ+BG/9esThQXsYcWgvWqKQ==\r\n"\
"-----END CERTIFICATE-----\r\n"\
"\r\n"