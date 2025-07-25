@{
    RootModule        = 'mompfdie.coretools.psm1'
    ModuleVersion     = '1.0.0'
    GUID              = 'b7c2e437-56b7-4b89-9e85-2d9e9d84a345'
    Author            = 'Raimund Plie�nig'
    CompanyName       = 'Die Mompfdies'
    Copyright         = '(c) Raimund Plie�nig. All rights reserved.'
    Description       = 'Core Tools Module f�r wiederverwendbare Steuer- und Loggingfunktionen in PowerShell-Skripten (IceSelfCheckIn, Hausautomatisierung, etc.)'
    PowerShellVersion = '5.1'

    FunctionsToExport = @(
        'Test-TaskDue',
        'Update-TaskStatus',
        'Write-TaskLog',
        'Get-TaskConfig',
        'Start-TaskTranscriptIfVerbose',
        'Stop-TranscriptIfRunning',
        'New-MompfdieEventLog',
        'New-MompfdieEventLogSource',
        'Write-MompfdieEventLog'
    )

    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()

    PrivateData = @{
        PSData = @{
            Tags         = @('Logging', 'Registry', 'EventLog', 'Transcript', 'ScheduledTasks', 'IceSelfCheckIn')
            LicenseUri   = ''
            ProjectUri   = 'https://github.com/theMompfdie/mompfdie.coretools'
            ReleaseNotes = 'Initial release with core task execution, logging and EventLog helpers.'
        }
    }
} 
# SIG # Begin signature block
# MIIrsAYJKoZIhvcNAQcCoIIroTCCK50CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUfBpm65ePM9LLH1ZKCkdARZgP
# 7jmggiU2MIIFjTCCBHWgAwIBAgIQDpsYjvnQLefv21DiCEAYWjANBgkqhkiG9w0B
# AQwFADBlMQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYD
# VQQLExB3d3cuZGlnaWNlcnQuY29tMSQwIgYDVQQDExtEaWdpQ2VydCBBc3N1cmVk
# IElEIFJvb3QgQ0EwHhcNMjIwODAxMDAwMDAwWhcNMzExMTA5MjM1OTU5WjBiMQsw
# CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
# ZGlnaWNlcnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQw
# ggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC/5pBzaN675F1KPDAiMGkz
# 7MKnJS7JIT3yithZwuEppz1Yq3aaza57G4QNxDAf8xukOBbrVsaXbR2rsnnyyhHS
# 5F/WBTxSD1Ifxp4VpX6+n6lXFllVcq9ok3DCsrp1mWpzMpTREEQQLt+C8weE5nQ7
# bXHiLQwb7iDVySAdYyktzuxeTsiT+CFhmzTrBcZe7FsavOvJz82sNEBfsXpm7nfI
# SKhmV1efVFiODCu3T6cw2Vbuyntd463JT17lNecxy9qTXtyOj4DatpGYQJB5w3jH
# trHEtWoYOAMQjdjUN6QuBX2I9YI+EJFwq1WCQTLX2wRzKm6RAXwhTNS8rhsDdV14
# Ztk6MUSaM0C/CNdaSaTC5qmgZ92kJ7yhTzm1EVgX9yRcRo9k98FpiHaYdj1ZXUJ2
# h4mXaXpI8OCiEhtmmnTK3kse5w5jrubU75KSOp493ADkRSWJtppEGSt+wJS00mFt
# 6zPZxd9LBADMfRyVw4/3IbKyEbe7f/LVjHAsQWCqsWMYRJUadmJ+9oCw++hkpjPR
# iQfhvbfmQ6QYuKZ3AeEPlAwhHbJUKSWJbOUOUlFHdL4mrLZBdd56rF+NP8m800ER
# ElvlEFDrMcXKchYiCd98THU/Y+whX8QgUWtvsauGi0/C1kVfnSD8oR7FwI+isX4K
# Jpn15GkvmB0t9dmpsh3lGwIDAQABo4IBOjCCATYwDwYDVR0TAQH/BAUwAwEB/zAd
# BgNVHQ4EFgQU7NfjgtJxXWRM3y5nP+e6mK4cD08wHwYDVR0jBBgwFoAUReuir/SS
# y4IxLVGLp6chnfNtyA8wDgYDVR0PAQH/BAQDAgGGMHkGCCsGAQUFBwEBBG0wazAk
# BggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMEMGCCsGAQUFBzAC
# hjdodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRBc3N1cmVkSURS
# b290Q0EuY3J0MEUGA1UdHwQ+MDwwOqA4oDaGNGh0dHA6Ly9jcmwzLmRpZ2ljZXJ0
# LmNvbS9EaWdpQ2VydEFzc3VyZWRJRFJvb3RDQS5jcmwwEQYDVR0gBAowCDAGBgRV
# HSAAMA0GCSqGSIb3DQEBDAUAA4IBAQBwoL9DXFXnOF+go3QbPbYW1/e/Vwe9mqyh
# hyzshV6pGrsi+IcaaVQi7aSId229GhT0E0p6Ly23OO/0/4C5+KH38nLeJLxSA8hO
# 0Cre+i1Wz/n096wwepqLsl7Uz9FDRJtDIeuWcqFItJnLnU+nBgMTdydE1Od/6Fmo
# 8L8vC6bp8jQ87PcDx4eo0kxAGTVGamlUsLihVo7spNU96LHc/RzY9HdaXFSMb++h
# UD38dglohJ9vytsgjTVgHAIDyyCwrFigDkBjxZgiwbJZ9VVrzyerbHbObyMt9H5x
# aiNrIv8SuFQtJ37YOtnwtoeW/VvRXKwYw02fc7cBqZ9Xql4o4rmUMIIGtDCCBJyg
# AwIBAgIQDcesVwX/IZkuQEMiDDpJhjANBgkqhkiG9w0BAQsFADBiMQswCQYDVQQG
# EwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cuZGlnaWNl
# cnQuY29tMSEwHwYDVQQDExhEaWdpQ2VydCBUcnVzdGVkIFJvb3QgRzQwHhcNMjUw
# NTA3MDAwMDAwWhcNMzgwMTE0MjM1OTU5WjBpMQswCQYDVQQGEwJVUzEXMBUGA1UE
# ChMORGlnaUNlcnQsIEluYy4xQTA/BgNVBAMTOERpZ2lDZXJ0IFRydXN0ZWQgRzQg
# VGltZVN0YW1waW5nIFJTQTQwOTYgU0hBMjU2IDIwMjUgQ0ExMIICIjANBgkqhkiG
# 9w0BAQEFAAOCAg8AMIICCgKCAgEAtHgx0wqYQXK+PEbAHKx126NGaHS0URedTa2N
# DZS1mZaDLFTtQ2oRjzUXMmxCqvkbsDpz4aH+qbxeLho8I6jY3xL1IusLopuW2qft
# JYJaDNs1+JH7Z+QdSKWM06qchUP+AbdJgMQB3h2DZ0Mal5kYp77jYMVQXSZH++0t
# rj6Ao+xh/AS7sQRuQL37QXbDhAktVJMQbzIBHYJBYgzWIjk8eDrYhXDEpKk7RdoX
# 0M980EpLtlrNyHw0Xm+nt5pnYJU3Gmq6bNMI1I7Gb5IBZK4ivbVCiZv7PNBYqHEp
# NVWC2ZQ8BbfnFRQVESYOszFI2Wv82wnJRfN20VRS3hpLgIR4hjzL0hpoYGk81coW
# J+KdPvMvaB0WkE/2qHxJ0ucS638ZxqU14lDnki7CcoKCz6eum5A19WZQHkqUJfdk
# DjHkccpL6uoG8pbF0LJAQQZxst7VvwDDjAmSFTUms+wV/FbWBqi7fTJnjq3hj0Xb
# Qcd8hjj/q8d6ylgxCZSKi17yVp2NL+cnT6Toy+rN+nM8M7LnLqCrO2JP3oW//1sf
# uZDKiDEb1AQ8es9Xr/u6bDTnYCTKIsDq1BtmXUqEG1NqzJKS4kOmxkYp2WyODi7v
# QTCBZtVFJfVZ3j7OgWmnhFr4yUozZtqgPrHRVHhGNKlYzyjlroPxul+bgIspzOwb
# tmsgY1MCAwEAAaOCAV0wggFZMBIGA1UdEwEB/wQIMAYBAf8CAQAwHQYDVR0OBBYE
# FO9vU0rp5AZ8esrikFb2L9RJ7MtOMB8GA1UdIwQYMBaAFOzX44LScV1kTN8uZz/n
# upiuHA9PMA4GA1UdDwEB/wQEAwIBhjATBgNVHSUEDDAKBggrBgEFBQcDCDB3Bggr
# BgEFBQcBAQRrMGkwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLmRpZ2ljZXJ0LmNv
# bTBBBggrBgEFBQcwAoY1aHR0cDovL2NhY2VydHMuZGlnaWNlcnQuY29tL0RpZ2lD
# ZXJ0VHJ1c3RlZFJvb3RHNC5jcnQwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2Ny
# bDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1c3RlZFJvb3RHNC5jcmwwIAYDVR0g
# BBkwFzAIBgZngQwBBAIwCwYJYIZIAYb9bAcBMA0GCSqGSIb3DQEBCwUAA4ICAQAX
# zvsWgBz+Bz0RdnEwvb4LyLU0pn/N0IfFiBowf0/Dm1wGc/Do7oVMY2mhXZXjDNJQ
# a8j00DNqhCT3t+s8G0iP5kvN2n7Jd2E4/iEIUBO41P5F448rSYJ59Ib61eoalhnd
# 6ywFLerycvZTAz40y8S4F3/a+Z1jEMK/DMm/axFSgoR8n6c3nuZB9BfBwAQYK9FH
# aoq2e26MHvVY9gCDA/JYsq7pGdogP8HRtrYfctSLANEBfHU16r3J05qX3kId+ZOc
# zgj5kjatVB+NdADVZKON/gnZruMvNYY2o1f4MXRJDMdTSlOLh0HCn2cQLwQCqjFb
# qrXuvTPSegOOzr4EWj7PtspIHBldNE2K9i697cvaiIo2p61Ed2p8xMJb82Yosn0z
# 4y25xUbI7GIN/TpVfHIqQ6Ku/qjTY6hc3hsXMrS+U0yy+GWqAXam4ToWd2UQ1KYT
# 70kZjE4YtL8Pbzg0c1ugMZyZZd/BdHLiRu7hAWE6bTEm4XYRkA6Tl4KSFLFk43es
# aUeqGkH/wyW4N7OigizwJWeukcyIPbAvjSabnf7+Pu0VrFgoiovRDiyx3zEdmcif
# /sYQsfch28bZeUz2rtY/9TCA6TD8dC3JE3rYkrhLULy7Dc90G6e8BlqmyIjlgp2+
# VqsS9/wQD7yFylIz0scmbKvFoW2jNrbM1pD2T7m3XDCCBu0wggTVoAMCAQICEAqA
# 7xhLjfEFgtHEdqeVdGgwDQYJKoZIhvcNAQELBQAwaTELMAkGA1UEBhMCVVMxFzAV
# BgNVBAoTDkRpZ2lDZXJ0LCBJbmMuMUEwPwYDVQQDEzhEaWdpQ2VydCBUcnVzdGVk
# IEc0IFRpbWVTdGFtcGluZyBSU0E0MDk2IFNIQTI1NiAyMDI1IENBMTAeFw0yNTA2
# MDQwMDAwMDBaFw0zNjA5MDMyMzU5NTlaMGMxCzAJBgNVBAYTAlVTMRcwFQYDVQQK
# Ew5EaWdpQ2VydCwgSW5jLjE7MDkGA1UEAxMyRGlnaUNlcnQgU0hBMjU2IFJTQTQw
# OTYgVGltZXN0YW1wIFJlc3BvbmRlciAyMDI1IDEwggIiMA0GCSqGSIb3DQEBAQUA
# A4ICDwAwggIKAoICAQDQRqwtEsae0OquYFazK1e6b1H/hnAKAd/KN8wZQjBjMqiZ
# 3xTWcfsLwOvRxUwXcGx8AUjni6bz52fGTfr6PHRNv6T7zsf1Y/E3IU8kgNkeECqV
# Q+3bzWYesFtkepErvUSbf+EIYLkrLKd6qJnuzK8Vcn0DvbDMemQFoxQ2Dsw4vEjo
# T1FpS54dNApZfKY61HAldytxNM89PZXUP/5wWWURK+IfxiOg8W9lKMqzdIo7VA1R
# 0V3Zp3DjjANwqAf4lEkTlCDQ0/fKJLKLkzGBTpx6EYevvOi7XOc4zyh1uSqgr6Un
# bksIcFJqLbkIXIPbcNmA98Oskkkrvt6lPAw/p4oDSRZreiwB7x9ykrjS6GS3NR39
# iTTFS+ENTqW8m6THuOmHHjQNC3zbJ6nJ6SXiLSvw4Smz8U07hqF+8CTXaETkVWz0
# dVVZw7knh1WZXOLHgDvundrAtuvz0D3T+dYaNcwafsVCGZKUhQPL1naFKBy1p6ll
# N3QgshRta6Eq4B40h5avMcpi54wm0i2ePZD5pPIssoszQyF4//3DoK2O65Uck5Wg
# gn8O2klETsJ7u8xEehGifgJYi+6I03UuT1j7FnrqVrOzaQoVJOeeStPeldYRNMmS
# F3voIgMFtNGh86w3ISHNm0IaadCKCkUe2LnwJKa8TIlwCUNVwppwn4D3/Pt5pwID
# AQABo4IBlTCCAZEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQU5Dv88jHt/f3X85Fx
# YxlQQ89hjOgwHwYDVR0jBBgwFoAU729TSunkBnx6yuKQVvYv1Ensy04wDgYDVR0P
# AQH/BAQDAgeAMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMIMIGVBggrBgEFBQcBAQSB
# iDCBhTAkBggrBgEFBQcwAYYYaHR0cDovL29jc3AuZGlnaWNlcnQuY29tMF0GCCsG
# AQUFBzAChlFodHRwOi8vY2FjZXJ0cy5kaWdpY2VydC5jb20vRGlnaUNlcnRUcnVz
# dGVkRzRUaW1lU3RhbXBpbmdSU0E0MDk2U0hBMjU2MjAyNUNBMS5jcnQwXwYDVR0f
# BFgwVjBUoFKgUIZOaHR0cDovL2NybDMuZGlnaWNlcnQuY29tL0RpZ2lDZXJ0VHJ1
# c3RlZEc0VGltZVN0YW1waW5nUlNBNDA5NlNIQTI1NjIwMjVDQTEuY3JsMCAGA1Ud
# IAQZMBcwCAYGZ4EMAQQCMAsGCWCGSAGG/WwHATANBgkqhkiG9w0BAQsFAAOCAgEA
# ZSqt8RwnBLmuYEHs0QhEnmNAciH45PYiT9s1i6UKtW+FERp8FgXRGQ/YAavXzWjZ
# hY+hIfP2JkQ38U+wtJPBVBajYfrbIYG+Dui4I4PCvHpQuPqFgqp1PzC/ZRX4pvP/
# ciZmUnthfAEP1HShTrY+2DE5qjzvZs7JIIgt0GCFD9ktx0LxxtRQ7vllKluHWiKk
# 6FxRPyUPxAAYH2Vy1lNM4kzekd8oEARzFAWgeW3az2xejEWLNN4eKGxDJ8WDl/FQ
# USntbjZ80FU3i54tpx5F/0Kr15zW/mJAxZMVBrTE2oi0fcI8VMbtoRAmaaslNXdC
# G1+lqvP4FbrQ6IwSBXkZagHLhFU9HCrG/syTRLLhAezu/3Lr00GrJzPQFnCEH1Y5
# 8678IgmfORBPC1JKkYaEt2OdDh4GmO0/5cHelAK2/gTlQJINqDr6JfwyYHXSd+V0
# 8X1JUPvB4ILfJdmL+66Gp3CSBXG6IwXMZUXBhtCyIaehr0XkBoDIGMUG1dUtwq1q
# mcwbdUfcSYCn+OwncVUXf53VJUNOaMWMts0VlRYxe5nK+At+DI96HAlXHAL5SlfY
# xJ7La54i71McVWRP66bW+yERNpbJCjyCYG2j+bdpxo/1Cy4uPcU3AWVPGrbn5PhD
# Bf3Froguzzhk++ami+r3Qrx5bIbY3TVzgiFI7Gq3zWcwggd/MIIFZ6ADAgECAhNZ
# AAABYGPQd5usmlfjAAAAAAFgMA0GCSqGSIb3DQEBCwUAMIH/MQswCQYDVQQGEwJB
# VDEVMBMGA1UECBMMTG93ZXJBdXN0cmlhMRcwFQYDVQQHEw5LbG9zdGVybmV1YnVy
# ZzEVMBMGA1UEChMMRGllTW9tcGZkaWVzMSAwHgYDVQQLExdGb3IgYXV0aG9yaXpl
# ZCB1c2Ugb25seTEoMCYGA1UECxMfQ2VydGlmaWNhdGlvbiBTZXJ2aWNlcyBEaXZp
# c2lvbjE4MDYGA1UEAxMvRGllIE1vbXBmZGllcyBTdWJvcmRpbmF0ZSBDZXJ0aWZp
# Y2F0ZSBBdXRob3JpdHkxIzAhBgkqhkiG9w0BCQEWFHBraUBkaWUtbW9tcGZkaWVz
# LmF0MB4XDTI1MDQyODE5NTk1N1oXDTI2MDQyODE5NTk1N1owgbAxFTATBgoJkiaJ
# k/IsZAEZFgVsb2NhbDEYMBYGCgmSJomT8ixkARkWCG1vbXBmZGllMRUwEwYDVQQL
# EwxEaWVNb21wZmRpZXMxDjAMBgNVBAsTBVRpZXIyMRAwDgYDVQQLEwdUMi1Vc2Vy
# MRowGAYDVQQDDBFSYWltdW5kIFBsaWXDn25pZzEoMCYGCSqGSIb3DQEJARYZbW9t
# cGZkaWVAZGllLW1vbXBmZGllcy5hdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCC
# AQoCggEBALrjLCMeJQ2zWs/SREGpN1dZe21RIlaRdnmVYJhuEF0Ds+j1CxLCu0jv
# fcgRk3yVpVE9iVQvUNvtt/kq5qk5rUa4qJwXI0iQHcVoaEs4lBSI4m4c7xhmWHZ4
# BHlU2ZTBMoxRUonrF6HTC7HTxAam47oUanDDeuA5MS9rvdq3MoAS57aF2GQ2LkYG
# KLeLP3XzcaU53/7+sJ4W+PNluDFso5CT/3TJtIueakNINqtJsVjCeDiIvUfr4iQW
# sly3iIvIE63saZVDLAndid3bgqVR9pksm7/uOW1rnYge0JlOxv4g/SELLbUKRNpP
# Xkw4izEbuEx9Wr8vivhqbSebj82+1SkCAwEAAaOCAj8wggI7MDwGCSsGAQQBgjcV
# BwQvMC0GJSsGAQQBgjcVCIGGjlPe7AmF5YU7gpPAWoXf8yqBJOz4YoeArEMCAWQC
# AQIwEwYDVR0lBAwwCgYIKwYBBQUHAwMwDgYDVR0PAQH/BAQDAgeAMBsGCSsGAQQB
# gjcVCgQOMAwwCgYIKwYBBQUHAwMwTgYJKwYBBAGCNxkCBEEwP6A9BgorBgEEAYI3
# GQIBoC8ELVMtMS01LTIxLTIyMDYzMDcyNTktOTkzMTYwODc5LTE0OTM2ODk5NTMt
# MTEwNTA0BgNVHREELTAroCkGCisGAQQBgjcUAgOgGwwZTW9tcGZkaWVAZGllLW1v
# bXBmZGllcy5hdDAdBgNVHQ4EFgQUJ4EZRst6nIKdbG2PZJChaaTpp8IwHwYDVR0j
# BBgwFoAUYzqCNokgjeDVrILuNGu1Ja/CjVQwcwYDVR0fBGwwajBooGagZIZiaHR0
# cDovL3BraS5kaWUtbW9tcGZkaWVzLmF0L0NlcnRFbnJvbGwvRGllJTIwTW9tcGZk
# aWVzJTIwU3Vib3JkaW5hdGUlMjBDZXJ0aWZpY2F0ZSUyMEF1dGhvcml0eS5jcmww
# fgYIKwYBBQUHAQEEcjBwMG4GCCsGAQUFBzAChmJodHRwOi8vcGtpLmRpZS1tb21w
# ZmRpZXMuYXQvQ2VydEVucm9sbC9EaWUlMjBNb21wZmRpZXMlMjBTdWJvcmRpbmF0
# ZSUyMENlcnRpZmljYXRlJTIwQXV0aG9yaXR5LmNydDANBgkqhkiG9w0BAQsFAAOC
# AgEAM4+Z91wX6ceczqUKRRZcBYDdOTdTWuBpd92cxqcwGJA2InhrK2zURyMXj3Kh
# NF9gaRd+vdTr8siw6neUA/4+2PFV/36zz/C7jTJga7/y4GHZTXl3Aj/JY7d+4w4H
# REiyIvWuTTwVLWyFV6gYyc6qiEOU0Da8K43pS9R6VfMm5kef0wV9QK0PfBPSbRFd
# MLoHr37QKeNEwvbfuBFMKgg/OssiaWEk2k6nOHgtoL2o7aL+ahbNPn2QRhzUXi+B
# rhD/B59zRNgCqy3rOKX7XSTPHI4IKeL8038yszshAoTKazJQ10bVU6TVRhQuK1PP
# js+wU8furrs9z4H/N9YSPIaI/lG0LR30c42NPm9u63pb62jL1LYBsb6GMWpctedQ
# eHmCBNXO+/znOzGdLNHu1MC4AzvICREA0uxP48CXXFHXX5fnx8XJDDzRdC8VNyIU
# EMUvnr8++vV/u1mF9Dz4amyUgZ8dRBDTcUuLOcdrdnOkfAG4lDzSqJdpmZSD3rNG
# QYto3IEOHfJokvc7M+WvdKghMyacoXBvb8XUFSkMdHD17KzZAokNvtg18uOfVxr0
# tXK3TpMkYx6eEnmtyOoFmlxG3eAxvWXLv+SXuTz7utKYIbvX3UYrXY7otIylUI7L
# ZUmbaF+kD3i5QKpT1Z3Z3LrBqG05nFHdmz7o/Z8D/8O+7kQwggp1MIIIXaADAgEC
# AhNqAAAABCwOPSeUnAMfAAAAAAAEMA0GCSqGSIb3DQEBCwUAMIH4MSMwIQYJKoZI
# hvcNAQkBFhRwa2lAZGllLW1vbXBmZGllcy5hdDELMAkGA1UEBhMCQVQxFTATBgNV
# BAgTDExvd2VyQXVzdHJpYTEXMBUGA1UEBxMOS2xvc3Rlcm5ldWJ1cmcxFTATBgNV
# BAoTDERpZU1vbXBmZGllczEgMB4GA1UECxMXRm9yIGF1dGhvcml6ZWQgdXNlIG9u
# bHkxKDAmBgNVBAsTH0NlcnRpZmljYXRpb24gU2VydmljZXMgRGl2aXNpb24xMTAv
# BgNVBAMTKERpZSBNb21wZmRpZXMgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkw
# HhcNMjAwMjIzMTM0MTQ5WhcNMzAwMjIzMTM1MTQ5WjCB/zELMAkGA1UEBhMCQVQx
# FTATBgNVBAgTDExvd2VyQXVzdHJpYTEXMBUGA1UEBxMOS2xvc3Rlcm5ldWJ1cmcx
# FTATBgNVBAoTDERpZU1vbXBmZGllczEgMB4GA1UECxMXRm9yIGF1dGhvcml6ZWQg
# dXNlIG9ubHkxKDAmBgNVBAsTH0NlcnRpZmljYXRpb24gU2VydmljZXMgRGl2aXNp
# b24xODA2BgNVBAMTL0RpZSBNb21wZmRpZXMgU3Vib3JkaW5hdGUgQ2VydGlmaWNh
# dGUgQXV0aG9yaXR5MSMwIQYJKoZIhvcNAQkBFhRwa2lAZGllLW1vbXBmZGllcy5h
# dDCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAOYwa8tKv9cx+VTTrfC/
# yGyHpgJQnJ3+7Q6cREXe6Va1ldDhkqQ+xSC/EcRojf25iou4BIdXMTwuwXum4LGT
# n1bgxNOJLUMxeiGlBaIlKK0W9QeXy9Duz4a+MQT4e/QIlfELotlJmsfaR1INXiL3
# tVNtW56v+t6cZB2GTFd56BlMSXJXwCkKOnjOFqSuyxRmeCS9Z4GRoFu+W65LieiS
# hJdxppTNVb7mmIYBowe/OSmG9hNfYlv4I6czY55YXcuXvLvWASeIgBPMS1FUUeAe
# puNbkAK9kXfbpAHyXlWwXeRceEW6DbwmwKGbd30au0WD1BndUMb2YQDWriNiRpj3
# n5V76hVX1zTLe0TLTWKPZ1kNNmFBVh52aTr5iKHzdIGRIuCHJILQq+4hxGDIjeeA
# IeKJAt35NvYqe0CTJCa8W6hCrEcwXqx57iAgEJdmKf7O3HyBlGF+XtQEPtk3Z69X
# NR/knQ9r6EkgWC+S6TL/OUQ+iX72QCh3i+O/3SpmqbzlNxGryYgHZAYxdY/CNYXq
# g9+0tgShDxQnH9STjhtEQ0+eIblHRWDJkNyw+BmWdfrT4csAfUu0w9gkpJM7PuhL
# VCY45Y4D1Bi+GcTDwQAcHyIsIXWItQP5+BEvvSqNgljj/CSlxaE+vIvZ4xaClRG5
# hWFavuP35c2VFBp7UCojHGydAgMBAAGjggPtMIID6TAQBgkrBgEEAYI3FQEEAwIB
# ADAdBgNVHQ4EFgQUYzqCNokgjeDVrILuNGu1Ja/CjVQwggJwBgNVHSAEggJnMIIC
# YzCCAl8GCCsGAQQBg65sMIICUTCCAgYGCCsGAQUFBwICMIIB+B6CAfQAVABoAGkA
# cwAgAEUAbgB0AGUAcgBwAHIAaQBzAGUAIABDAGUAcgB0AGkAZgBpAGMAYQB0AGkA
# bwBuACAAQQB1AHQAaABvAHIAaQB0AHkAIABpAHMAIABhAG4AIABpAG4AdABlAHIA
# bgBhAGwAIAByAGUAcwBvAHUAcgBjAGUALgAgACAAQwBlAHIAdABpAGYAaQBjAGEA
# dABlAHMAIABpAHMAcwB1AGUAZAAgAGIAeQAgAHQAaABpAHMAIABDAEEAIABhAHIA
# ZQAgAGYAbwByACAAaQBuAHQAZQByAG4AYQBsACAAdQBzAGUAIABvAG4AbAB5AC4A
# IAAgAEYAbwByACAAbQBvAHIAZQAgAGkAbgBmAG8AcgBtAGEAdABpAG8AbgAsACAA
# cABsAGUAYQBzAGUAIAByAGUAZgBlAHIAIAB0AG8AIAB0AGgAZQAgAEMAZQByAHQA
# aQBmAGkAYwBhAHQAaQBvAG4AIABQAHIAYQBjAHQAaQBjAGUAIABTAHQAYQB0AGUA
# bQBlAG4AdAAgAGEAdAAgAGgAdAB0AHAAOgAvAC8AcABrAGkALgBkAGkAZQAtAG0A
# bwBtAHAAZgBkAGkAZQBzAC4AYQB0AC8AQwBlAHIAdABFAG4AcgBvAGwAbAAvAGMA
# cABzAC4AaAB0AG0AbDBFBggrBgEFBQcCARY5aHR0cDovL3BraS5kaWUtbW9tcGZk
# aWVzLmF0L0NlcnRFbnJvbGwvc3ViTGVnYWxQb2xpY3kudHh0MBkGCSsGAQQBgjcU
# AgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEA
# MB8GA1UdIwQYMBaAFLUAhB42uIYbVN7YU+ZhlYmdxiReMGwGA1UdHwRlMGMwYaBf
# oF2GW2h0dHA6Ly9wa2kuZGllLW1vbXBmZGllcy5hdC9DZXJ0RW5yb2xsL0RpZSUy
# ME1vbXBmZGllcyUyMFJvb3QlMjBDZXJ0aWZpY2F0ZSUyMEF1dGhvcml0eS5jcmww
# dwYIKwYBBQUHAQEEazBpMGcGCCsGAQUFBzAChltodHRwOi8vcGtpLmRpZS1tb21w
# ZmRpZXMuYXQvQ2VydEVucm9sbC9EaWUlMjBNb21wZmRpZXMlMjBSb290JTIwQ2Vy
# dGlmaWNhdGUlMjBBdXRob3JpdHkuY3J0MA0GCSqGSIb3DQEBCwUAA4ICAQCoPHD6
# Z48y5m4dWYp588G+66OR8c3mLLPbTuDWSXBzkjnPLxy7QqUDYW2i497dcDeFCbWP
# UmMfD3RnZs9jr46sQh5Wm+hl2hQds1SwbxeBy/RlxaGtlmg9f7IyYoc20li2eWq5
# se7IqtKwGUHzdP3FqsaDJ6QglioVDpAZYKWV4yI2jCQIRO5A6Ji2086u09T4EKej
# 4iZ9Ii1cZ2kGEUBBh9oziAa/CDqu14hSKrqBZSW6a+FXjRCDMZlKmqbR1/hBGVtw
# Dw0NGm+bIj/nhZxMYtNeiI45nfyMlL4h9Cr6ormtGNVgErVkFF3iIKDhgj1TS5Pl
# CcHFvbVg/IVghU/X+XDfYl198f6YFHWZYBWkl5rakX78W8JdGttCtMmaDPGCgAFh
# azXtmW1DVF1aLsbflHVxkqxsYuKfkEBlKEGvynrMwD9OQilN2k1I9iZcmhZFUll2
# mzAoWsPLX3739/2tDiU6m+NUInO4hKZJYVklA9a2cJ4mDZTAIsBRPNmIb/S5rv/i
# OxXYSSTvwg1TeD9x1YoRNmZr68wOTH3qz5TqOhPBkgyG3gBrmZu1CfAKc+L8SfyS
# x6KEZnRr/IZD99M0Q6hsljDxcX7jDAqY/LTwUYqtC6EirOZOoC1B7h66SbllsFng
# PdQXrC0ylKXYJ3dnEY3tnRyJsxpyF0+A2QWdhTGCBeQwggXgAgEBMIIBFzCB/zEL
# MAkGA1UEBhMCQVQxFTATBgNVBAgTDExvd2VyQXVzdHJpYTEXMBUGA1UEBxMOS2xv
# c3Rlcm5ldWJ1cmcxFTATBgNVBAoTDERpZU1vbXBmZGllczEgMB4GA1UECxMXRm9y
# IGF1dGhvcml6ZWQgdXNlIG9ubHkxKDAmBgNVBAsTH0NlcnRpZmljYXRpb24gU2Vy
# dmljZXMgRGl2aXNpb24xODA2BgNVBAMTL0RpZSBNb21wZmRpZXMgU3Vib3JkaW5h
# dGUgQ2VydGlmaWNhdGUgQXV0aG9yaXR5MSMwIQYJKoZIhvcNAQkBFhRwa2lAZGll
# LW1vbXBmZGllcy5hdAITWQAAAWBj0HebrJpX4wAAAAABYDAJBgUrDgMCGgUAoHgw
# GAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGC
# NwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAjBgkqhkiG9w0BCQQx
# FgQU3iztem3hqlFvp6IUGXoETqVkTQYwDQYJKoZIhvcNAQEBBQAEggEARbYYXNQL
# X217kMTkklkGH4cKw13GgI+SBNThu8ZwKPgavbZOd1vSWlQz9l/lixWbGvoNfjDe
# dWkrX1NXqx4+TdTWo+Q7VfrKFPtgeDDTy1qqUyzRCeMiYlKN/j+bJSC44MkxRVY1
# G+2O7e6tX+55jIRwxmS4p+B8x/0qS+SIDqJw1laYZvxR0oozKCL8qyTsvQiXq/ta
# D98ozRLl8hxhP3j/nTLFrdCwpVPt0l2nsv3Tpaq+EbWwifWiklEThZF6TLohDDz8
# Bj1+Qad9jNKHnA60uLfdOWtuB99bvcVVWMQIr0sMin4Dpnrpml1Zns3o3WMAObu/
# Y2rBkQnmidTzP6GCAyYwggMiBgkqhkiG9w0BCQYxggMTMIIDDwIBATB9MGkxCzAJ
# BgNVBAYTAlVTMRcwFQYDVQQKEw5EaWdpQ2VydCwgSW5jLjFBMD8GA1UEAxM4RGln
# aUNlcnQgVHJ1c3RlZCBHNCBUaW1lU3RhbXBpbmcgUlNBNDA5NiBTSEEyNTYgMjAy
# NSBDQTECEAqA7xhLjfEFgtHEdqeVdGgwDQYJYIZIAWUDBAIBBQCgaTAYBgkqhkiG
# 9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNTA3MTYxOTMxMzNa
# MC8GCSqGSIb3DQEJBDEiBCB7qeBadWXmyOx7oseh7V9DRuFgYn1iIQdyfvzCN6Gz
# ITANBgkqhkiG9w0BAQEFAASCAgBJDUTdXgVWaokOuNSe6hl0ZYPhuroRiaTbwtTI
# nCPMroke1gC9/eQ+Hp4NYcIKC4/jSHMZzyez+AfdTu8fRHiv9E2w85sT1ro4Tt0r
# pEjxcAQriyznHZ/qyoy06JF/OkO+03Jp8ErZrhzfH8zqiGKMF5L3RbfleKZ6iHjA
# VYABmIaNNdbb9oETP/igWoBmjV1yR178nxKAtZsqMhgokRfrKONDBCjPvTgW42O1
# IVilFwHbfLhNElfzsOXq/Uz+704a3mAH5Iaw6EpH8hzCIpXX49ykPN6CfGMOW5f1
# ah+6Fovf+Xr7SyOfr/S8uUAzJAFUYen6DviFcgGVTWys5nxv7ESI9nWkpki9p2KR
# RPtIyjbnGTLxcAKtRFspHvurbQDQ8oKXoIjVpOBpPB7PGBInYGx3PW0yjqtNmBh3
# KWR3W+KkejWRdwrxgKEWQbwaup0Le1qAvv7t7+JIUqpPqAH46zXJRfWUQ9lpLsq8
# +SR5XgzQeKVJICs/hEAJu638QfVWZ/B99ZvouOzw+fX+iecanZG5R4BOIz3Xsqju
# Nizh3CqIsoAbrNCZKd/poU4F9WNAGUswtXRe8UECML3fktjST42n9fCbjZKcs9BP
# Quc+gvgcIUqsftuBJMn5vt/EEhvDeZxTMvKrNcvmaXC159XB4LAWbB0h9VlLm6K1
# O+sMBQ==
# SIG # End signature block
