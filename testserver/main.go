package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

type application struct {
	auth struct {
		username string
		password string
	}
}

func main() {
	app := new(application)

	app.auth.username = os.Getenv("AUTH_USERNAME")
	app.auth.password = os.Getenv("AUTH_PASSWORD")

	if app.auth.username == "" {
		log.Fatal("basic auth username must be provided")
	}

	if app.auth.password == "" {
		log.Fatal("basic auth password must be provided")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", app.indexHandler)
	mux.HandleFunc("/csp", app.cspHandler)
	mux.HandleFunc("/other", app.otherHandler)
	mux.HandleFunc("/protected", app.basicAuth(app.protectedHandler))
	mux.HandleFunc("/slow", app.slowHandler)

	srv := &http.Server{
		Addr:         ":8080",
		Handler:      mux,
		IdleTimeout:  time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	srvS := &http.Server{
		Addr:         ":8081",
		Handler:      mux,
		IdleTimeout:  time.Minute,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second,
	}

	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()

		log.Printf("starting server on %s with self signed TLS certs", srvS.Addr)
		err := srvS.ListenAndServeTLS("./localhost.pem", "./localhost-key.pem")
		log.Fatal(err)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()

		log.Printf("starting server on %s with no TLS", srv.Addr)
		err := srv.ListenAndServe()
		log.Fatal(err)
	}()

	wg.Wait()
}

func (app *application) indexHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, `
	<!DOCTYPE html>
<html>
<head>
</head>
<body>

<table>
<tr>
<td><a href="/csp">/csp</a></td>
<td>Test CSP (look in console)</td>
</tr>
<tr>
<td><a href="/other">/other</a></td>
<td>Go here for most tests</td>
</tr>
<tr>
<td><a href="/protected">/protected</a></td>
<td>Test for basic auth</td>
</tr>
<tr>
<td><a href="/slow">/slow</a></td>
<td>You'll get a response back after 200ms</td>
</tr>
</table>

</body>
</html>`)
}

func (app *application) slowHandler(w http.ResponseWriter, r *http.Request) {
	time.Sleep(time.Millisecond * 200)
	fmt.Fprintf(w, "Sorry, that was slow")
}

func (app *application) protectedHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, admin")
}

func (app *application) cspHandler(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Add("Content-Security-Policy", "default-src https:")
	fmt.Fprintf(w, "Hello, CSP tester")
}

func (app *application) otherHandler(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:   "hello-world-go",
		Value:  "this is a test cookie, yum!",
		MaxAge: 3600,
	})

	fmt.Fprintf(w, `
	<!DOCTYPE html>
<html>
<head>
<script>
function getCookies() {
	const cookiesDisplay = document.getElementById("cookies-demo");
	cookiesDisplay.textContent = "Cookies: " + document.cookie;
}

function getUserAgent() {
	const uaDisplay = document.getElementById("useragent-demo");
	uaDisplay.textContent = "Your UserAgent: " + navigator.userAgent;
}

function getTimezone() {
	const tzDisplay = document.getElementById("tz-demo");
	tzDisplay.textContent = "Timezone: " + Intl.DateTimeFormat().resolvedOptions().timeZone;
}

function networkStatus() {
	const statusDisplay = document.getElementById("network-demo");
	statusDisplay.textContent = "Network Status: " + navigator.onLine;
}

function getGeolocation() {
	navigator.geolocation.getCurrentPosition(function(position) {
		let lat = position.coords.latitude;
		let long = position.coords.longitude;

		document.getElementById("demo").innerHTML = "Lat: " + lat.toFixed(2) + " Long: " + long.toFixed(2) + "";
	});
}

function getLocale() {
	const userLocale =
  navigator.languages && navigator.languages.length
    ? navigator.languages[0]
    : navigator.language;

	document.getElementById("locale-demo").innerHTML = userLocale;
}
</script>
</head>
<body onload="getLocale(); getTimezone(); getUserAgent(); networkStatus(); getCookies();">

<table>
<tr>
<td><button type="button" onclick="getGeolocation()">Get geolocation</button></td>
<td><p id="demo">Lat: ? Long: ?</p></td>
</tr>
<tr>
<td>NA</td>
<td><p id="locale-demo">Locale: ?</p></td>
</tr>
<tr>
<td><button type="button" onclick="networkStatus()">Refresh network status</button></td>
<td><p id="network-demo">Network Status: ?</p></td>
</tr>
<tr>
<td>NA</td>
<td><p id="tz-demo">Timezone: ?</p></td>
</tr>
<tr>
<td>NA</td>
<td><p id="useragent-demo">Your UserAgent: ?</p></td>
</tr>
<tr>
<td><button type="button" onclick="getCookies()">Refresh cookies</button></td>
<td><p id="cookies-demo">Cookies: ?</p></td>
</tr>
</table>

</body>
</html>`)
}

func (app *application) basicAuth(next http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if ok {
			usernameHash := sha256.Sum256([]byte(username))
			passwordHash := sha256.Sum256([]byte(password))
			expectedUsernameHash := sha256.Sum256([]byte(app.auth.username))
			expectedPasswordHash := sha256.Sum256([]byte(app.auth.password))

			usernameMatch := (subtle.ConstantTimeCompare(usernameHash[:], expectedUsernameHash[:]) == 1)
			passwordMatch := (subtle.ConstantTimeCompare(passwordHash[:], expectedPasswordHash[:]) == 1)

			if usernameMatch && passwordMatch {
				next.ServeHTTP(w, r)
				return
			}
		}

		w.Header().Set("WWW-Authenticate", `Basic realm="restricted", charset="UTF-8"`)
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	})
}
