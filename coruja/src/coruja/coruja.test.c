#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <coruja/coruja.h>

static const char* cert_1 = "-----BEGIN CERTIFICATE-----\n"
"MIIG9DCCBdygAwIBAgISAwlZX3toja8spIxSXHTKF+FyMA0GCSqGSIb3DQEBCwUA\n"
"MDIxCzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQD\n"
"EwJSMzAeFw0yMDEyMDMxNDAwNTJaFw0yMTAzMDMxNDAwNTJaMB4xHDAaBgNVBAMM\n"
"Eyouc3RhY2tleGNoYW5nZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK\n"
"AoIBAQCv/JcuNRZQmB5/e6vDoud+eNc/tp3Eu65I4NgLVQ28oX8ORtdpJD10pw1g\n"
"oArHnf1j9jLFZbe6B5sWZq990rNnjKOra5YksxFMYmCC0HgoPmqBnz43mrEKgBrj\n"
"JIuVCrOqVWEtia1oc2uIQSkawgIuGf5I+unQA+vspp1H9DaE70/tBtd0kpy6m5KZ\n"
"0PsibrjWGrW5leTB5q7w0e0l6Bh73hJnsfI5oKlQDx8uIJ9GThrFAfk+Xx4iZUwz\n"
"b2XJLg3RpPqqFmgBEIo9HC1Gxphn9NZbnvi1J1adFA4nfQh7uElt4dh6A3uwmWln\n"
"riPZ8Mt0T539tYl+x6j6Z6QyCRB1AgMBAAGjggQWMIIEEjAOBgNVHQ8BAf8EBAMC\n"
"BaAwHQYDVR0lBBYwFAYIKwYBBQUHAwEGCCsGAQUFBwMCMAwGA1UdEwEB/wQCMAAw\n"
"HQYDVR0OBBYEFKyYhPGAVlTGYHx0ErZRgwSRyek+MB8GA1UdIwQYMBaAFBQusxe3\n"
"WFbLrlAJQOYfr52LFMLGMFUGCCsGAQUFBwEBBEkwRzAhBggrBgEFBQcwAYYVaHR0\n"
"cDovL3IzLm8ubGVuY3Iub3JnMCIGCCsGAQUFBzAChhZodHRwOi8vcjMuaS5sZW5j\n"
"ci5vcmcvMIIB5AYDVR0RBIIB2zCCAdeCDyouYXNrdWJ1bnR1LmNvbYISKi5ibG9n\n"
"b3ZlcmZsb3cuY29tghIqLm1hdGhvdmVyZmxvdy5uZXSCGCoubWV0YS5zdGFja2V4\n"
"Y2hhbmdlLmNvbYIYKi5tZXRhLnN0YWNrb3ZlcmZsb3cuY29tghEqLnNlcnZlcmZh\n"
"dWx0LmNvbYINKi5zc3RhdGljLm5ldIITKi5zdGFja2V4Y2hhbmdlLmNvbYITKi5z\n"
"dGFja292ZXJmbG93LmNvbYIVKi5zdGFja292ZXJmbG93LmVtYWlsgg8qLnN1cGVy\n"
"dXNlci5jb22CDWFza3VidW50dS5jb22CEGJsb2dvdmVyZmxvdy5jb22CEG1hdGhv\n"
"dmVyZmxvdy5uZXSCFG9wZW5pZC5zdGFja2F1dGguY29tgg9zZXJ2ZXJmYXVsdC5j\n"
"b22CC3NzdGF0aWMubmV0gg1zdGFja2FwcHMuY29tgg1zdGFja2F1dGguY29tghFz\n"
"dGFja2V4Y2hhbmdlLmNvbYISc3RhY2tvdmVyZmxvdy5ibG9nghFzdGFja292ZXJm\n"
"bG93LmNvbYITc3RhY2tvdmVyZmxvdy5lbWFpbIIRc3RhY2tzbmlwcGV0cy5uZXSC\n"
"DXN1cGVydXNlci5jb20wTAYDVR0gBEUwQzAIBgZngQwBAgEwNwYLKwYBBAGC3xMB\n"
"AQEwKDAmBggrBgEFBQcCARYaaHR0cDovL2Nwcy5sZXRzZW5jcnlwdC5vcmcwggEE\n"
"BgorBgEEAdZ5AgQCBIH1BIHyAPAAdwBc3EOS/uarRUSxXprUVuYQN/vV+kfcoXOU\n"
"sl7m9scOygAAAXYpHsnaAAAEAwBIMEYCIQD2BYPFaoNHxpuR7dpGPx90b2t2OFv1\n"
"oEELbqYiBWo4tAIhAKT8/8UQ6po+ONKkl4u9/hXrV424SewLQjyKuc656f/6AHUA\n"
"fT7y+I//iFVoJMLAyp5SiXkrxQ54CX8uapdomX4i8NcAAAF2KR7JpAAABAMARjBE\n"
"AiBk58dzHIsANdFi9Y305G6X1N1kGQVbZjrhIt4oQQooOAIgCi0yANzZULHUlKfF\n"
"WlNDSfKXHImI6W5vyF7XpkWt+HIwDQYJKoZIhvcNAQELBQADggEBAExNEHaf0ATu\n"
"kmLPA/FGKOi97vEieZv5QiKg2idsESsSc5XUcXjzHuz2ws+IYInd6gz6s3aua7c0\n"
"iCjwbkBuledtntKgvhBxB7ax4wcxt0vKY4yhcTifG+XpsdC2rjtIXO/Uckpn14tx\n"
"cUo4SsVqXLtxQu4qQ2DS3QGlyAwLPlPS46XkUP/ztd4D3WcyokUW72+2NMdtpgZq\n"
"NzteVkfQ5xb2akdrm2lN7/S2GBFPFzPGLUEwm0nxEPlF08kk3BWKlXfIWnCdHkrW\n"
"9mPoMo048BH4cVTwMDTR177IMxJY4p0uqsNMoPvTpvNIqbIl5bv3uABROg0Y8yLq\n"
"4CZZLJFwyL0=\n"
"-----END CERTIFICATE-----";

int main() {
    const char* crt = cert_1;
    size_t crt_size = strlen(crt);
    assert(coruja_parse_cert(crt, crt_size) == EXIT_SUCCESS);

    const char* urls[] = {
        "https://google.com",
        "http://github.com"
    };
    assert(coruja_check_urls(urls, 2) == EXIT_SUCCESS);
}
