# OAuth für PAIA

[Dieses Repository](https://github.com/gbv/paia-oauth) enthält Informationen zu
möglichen Erweiterungen der [PAIA-Spezifikation](https://gbv.github.com/paia/)
und des [PAIA-Service der VZG](https://www.gbv.de/wikis/cls/PAIA) um weitere
Funktionen von [OAuth 2.0] (RFC 6749) und ggf. [OpenID Connect].

Mittels OAuth 2.0 kann Anwendungen gezielt **Zugriff auf einzelne Funktionen
von Benutzerkonten** gewährt und das Benutzerkonto zum Single-Sign-On (SSO) an
anderen Anwendungen verwendet werden. Da es sich eher um ein Framework mit
verschiedenen Möglichkeiten handelt, ist festzulegen, welche konkreten
Funktionen von OAuth 2.0 in welcher Form benötigt werden. Ein mögliches Profil
bietet OpenID Connect.

PAIA-Spezifikation (ab 1.2.0) und PAIA-Server der VZG setzen bereits OAuth 2.0
in einer einfachen Variante ("[Password Grant]") um.

## Grundlagen

[PAIA core]: http://gbv.github.io/paia/#paia-core
[PAIA auth]: http://gbv.github.io/paia/#paia-auth

In OAuth-Terminologie besteht der PAIA-Server aus einem **Resource Server**
([PAIA core]) und aus einem **Authorization Server** ([PAIA auth]).  Der
Resource Server bietet Zugriff auf Benutzerkonten mittels **[Access
Tokens](https://gbv.github.io/paia/#access-tokens-and-scopes)**, die vom
Authorization Server bereitgestellt werden.  

Access Tokens haben grundsätzlich eine begrenzte Gültigkeitsdauer und sind auf
bestimmt Zugriffsrechten (**Scopes**) beschränkt. Für PAIA core sind die Scopes
`read_patron`, `read_fees`, `read_items` und `write_items` möglich. 

OAuth 2.0 sieht verschiedene verschiedene Verfahren (**Grants**) vor, mit denen
Anwendungen wie die BibApp oder ein Benachrichtigungsserver (**Clients**) an
Access Tokens zum Zugriff auf PAIA core kommen können:

* [Password Grant]
* [Client Credentials Grant]
* [Authorization Code Grant]
* [Implicit Grant]

Darüber hinaus können weitere Grants festgelegt werden. Im Wesentlichen basiert
der Zugriff aus drei Teilen:

     +--------+                               +----------------------+
     |        |-- (1) Grant------------------>| Authorization Server |
     |        |<--(2) Access Token -----------| (PAIA auth)          |
     |        |                               +----------------------+
     | Client |
     |        |                                    +-----------------+
     |        |-- (3) Zugriff mitt Access Token -->| Resource Server |
     |        |<-----------------------------------| (PAIA core)     |
     +--------+                                    +-----------------+

Abgesehen vom [Password Grant] besteht der erste Teil (1) je nach Verfahren aus
mehreren Schritten in denen die Anwendung irgend einer Art von Zugangsdaten an
den Authorization Server übermittelt. Dafür muss sie zunächst dem Authorization
Server bekannt sein ([Registrierung von Anwendungen]) und sollte sich ihm gegenüber
authentifizieren ([Authentifizierung von Anwendungen]).

## Zugriffsverfahren (Grants)

### Password Grant

Beim [Resource Owner Password Credentials
Grant](http://tools.ietf.org/html/rfc6749#section-4.3) übermittelt die
Anwendung für jedes neue Access Token Benutzername und -passwort.

**Vorteile**

  * Einfach umzusetzen
  * Nach Preisgabe von Nutzerbame und Passwort ist kein weiteres 
    Eingreifen des Nutzers notwendig 
  * Anwendungen müssen nicht registriert werden
 
**Nachteile**

  * Jede Anwendung hat vollen Zugriff auf alle Funktionen
  * Zugriff kann nicht widerrufen werden
  * Potentiell unsicher und daher nicht empfohlen

Dieses Verfahren ist bereits seit Version 1.2.0 in der PAIA-Spezifikation
enthalten (PAIA auth [login](http://gbv.github.io/paia/paia.html#login)).

### Client Credentials Grant

[Client Credentials Grant](http://tools.ietf.org/html/rfc6749#section-4.4)
unterscheidet sich vom Passwort Credentials Grant darin, dass für jede
Anwendung eigene Zugangsdaten (`client_id` und `client_secret`) vergeben
werden. 

**Vorteile**

  * Es können abgestufte Zugriffsrechte vergeben werden
  * Die Zugangsdaten einer Anwendung können einzeln widerrufen werden

**Nachteile**

  * Die Anwendung muss auf sicherem Weg an ihre Zugangsdaten gelangen
  * Die Berechtigungen müsssen irgendwie verwaltet werden
  * Potentiell unsicher

Der Client Credentials Grant eignet sich am Besten für Anwendungen, die vom
Nutzer auf seinem eigenen Rechner selber ausgeführt werden und bietet somit nur
geringe Vorteile gegenüber dem Passwort Grant.  Client Credentials können
allerdings zur [Authentifizierung von Anwendungen] *zusätzlich* zu anderen
Verfahren verwendet werden.

Im Beispiel ist dieses Verfahren [unter "Eigene
Anwendungen"](oauth-applications.html) mit einem eigenen
[Konfigurationsformular](oauth-finanz.html) illustriert.

### Implicit Grant

Der [Implicit Grant](http://tools.ietf.org/html/rfc6749#section-4.2) (aka
"User-Agent Flow") bietet sich für JavaScript-basierte Webanwendungen an.
Ebenso wie beim folgenden Authorization Code Grant ist festgelegt wie Nutzer
der Anwendung explizit Zugriffsrechte einräumen können. Das Verfahren läuft in
der Praxis folgendermaßen ab:

1. Um Zugriff auf ein Benutzerkonto zu erhalten, schickt die Anwendung den
   Nutzer im Webbrowser an den Authorization-Server und teilt mit, welche
   Berechtigungen (scopes) sie gerne hätte: 

        https://paia.gbv.de/DE-Hil2/oauth?response_type=token
          &client_id=CLIENT_ID
          &redirect_uri=REDIRECT_URI
          &scope=read_patron%20read_items
          &state=...

2. Sofern der Nutzer nicht am Authorization Server angemeldet ist (Cookie),
   meldet er sich mit Nutzername und Passwort dort an (beachte, dasss die
   Anwendung in der ersten URL nicht mit angibt, für welchen Nutzer sie
   Berechtigungen möchte, dies ergibt sich implizit durch das Login).

3. Falls vom Nutzer (noch) keine Berechtigungen für die Anwendung vergeben
   wurden, bekommt er vom Authorization Server ein Bestätigungs-Formular
   präsentiert:

    * z.B. [BibApp](oauth-bibapp.html)
    * z.B. [Benachrichtigungsdienst](oauth-notify.html)
    * z.B. [Campus-Community](oauth-campus.html)

4. Nach Bestätigung des Nutzes oder direkt, falls der Nutzer der Anwendung
   schon früher die benötigten Berechtigungen erteilt hat, erfolgt direkt eine
   Weiterleitung an die zur Anwendung hinterlegten REDIRECT_URL. Dabei werden
   im Fragment-Identifier der URL Access Token und weitere Felder mitgeschickt,
   welche beim Password Grant als JSON-Objekt zurückgeliefert werden würden:

        https://bibapp.de/notify/callback#token_type=Bearer
          &scope=read_patron%20read_items
          &access_token=...
          &expires_in=...
          &state=...

5. Wenn der Nutzer nicht die benötigten Rechte erteilt, wird eine
   Fehler-Antwort an die REDIRECT_URL geschickt:

        https://bibapp.de/notify/callback#error=access_denied

6. Falls der Nutzer noch am Authorization Server angemeldet ist und den
   Zugriff schon bestätigt hatte, wird er direkt zur Anwendung umgeleitet,
   bekommt von der gesamten Transaktion also nichts mit.

**Vorteile**

  * Explizite Bestätigung durch Nutzer
  * Anwendung benötigt kein eigenes Passwort

**Nachteile**

  * PAIA auth benötigt eine Benutzeroberfläche
  * Nutzer müssen sich ggf. öfter mal beim Authentification Server anmelden, 
    wenn sowohl ihr Login als auch das Access Token der Anwendung abgelaufen
    sind.
  * Access Token sind nur schlecht gesichert (z.B. Browser-History)
 
### Authorization Code Grant

[Authorization Code Grant](http://tools.ietf.org/html/rfc6749#section-4.2) (aka
"Web Server Flow") bietet die meisten Möglichkeiten, ist jedoch auch in der
Implementierung umfangreicher. Der vollständige Ablauf ist hier dargestellt: 

     +---------+                                          +---------------+
     |         |---(1) client_id, redirect_uri & scope -->|               |
     | Browser |---(2) Nutzer meldet sich an ------------>| Authorization |
     |         |<--(3) Authorization Code ----------------|    Server     |
     +---------+                                          |               |
       ^    |                                             |  (PAIA auth)  |
       |   (3)                                            |               |
      (1)   |                                             |               |
       |    v                                             |               |
     +--------+                                           |               |
     |        |---(4) Authorization Code ---------------->|               |
     |        |<--(5) Access Token & Refresh Token -------|               |
     | Client |                                           |               |
     |        |---(8) Refresh Token --------------------->|               |
     |        |<--(9) Access Token & ggf. Refresh Token --|               |
     |        |                                           +---------------+
     +--------+                                 
        ^ |                                             +-----------------+
        | \----(6) Access Token ----------------------->| Resource Server |
        \------(7) Zugriff (bis Token abgelaufen) ------| (PAIA core)     |
                                                        +-----------------+


Das Verfahren läuft zunächst wie beim Implicit Grant ab:

1. Anwendung schickt Nutzer an Authorization Server, allerdings mit einem
   anderen `response_type`:

        https://paia.gbv.de/DE-Hil2/oauth?response_type=code
          &client_id=CLIENT_ID
          &redirect_uri=REDIRECT_URI
          &scope=read_patron%20read_items
          &state=...

2. Nutzer muss sich ggf. anmelden und beim ersten Zugriff die
   Zugriffsberechtigung erteilen (siehe Beispiel-Mockup
   [BibApp](oauth-bibapp.html), [Benachrichtigungsdienst](oauth-notify.html)
   und [Campus-Community](oauth-campus.html)).

3. Der Authorization Server leitet den Nutzer an die `redirect_uri` der
   Anwendung zurück, allerdings mit einem **Authorization Code**, der
   in der Query-Komponente der URL mitgeschickt wird: 

        https://bibapp.de/notify/callback?code=AUTH_CODE&state=...

    Im Fehlerfall wird der Fehler ebenfalls als Query-Parameter mitgeschickt:

        https://bibapp.de/notify/callback?error=...

4. Der Authorization Code hat nur eine sehr begrenzte Gültigkeitsdauer und
   dient lediglich dazu, ein erstes Access Token und ein **Refresh Token**
   anzufordern.  Dies geschieht über die PAIA auth Methode login, allerdings 
   mit einem anderen Anfrage-Parametern:

        POST https://paia.gbv.de/DE.Hil2/login
     
        grant_type=authorization_code
        &code=AUTH_CODE
        &client_id=CLIENT_ID
        &redirect_uri=REDIRECT_URI

    Die `redirect_uri` ist bei dieser Anfrage eigentlich überflüssig, da sie sich
    bei [Registrierung von Anwendungen] aus der `client_id` ergibt, muss aber laut
    Spezifikation nochmal mitgeschickt werden.

5. Die Antwort des Authorization Server enthält im Erfolgsfall neben dem
   Access Token eine Refresh Token:

        {
          "access_token": "...",
          "token_type": "Bearer",
          "expires_in": ...,
          "refresh_token": "REFRESH_TOKEN"
        }

6. Die Anwendung hat wie bei den anderen Grants Zugriff per Access Token...

7. ...bis das Access Token abgelaufen ist

8. Das Refresh Token hat im Gegensatz zum Access Token eine lange Gültigkeit
   (z.B. 1 Jahr) und wird nur benutzt um Access Token zu verlängern oder neue
   Access Tokens anzufordern. Dies geschieht ebenfalls an der PAIA auth Methode
   login. Auch hierbei wir empfohlen `client_id` und `client_secret` zur
   [Authentifizierung von Anwendungen] mitzuschicken:

        POST https://paia.gbv.de/DE.Hil2/login
    
        grant_type=refresh_token
        &refresh_token=REFRESH_TOKEN
        &scope=... (optional)

9. Die Antwort enthält im Erfolgsfall ein Access Token und ggf. auch ein neues
   Refresh Token. Refresh Tokens haben den Vorteil, dass sie nie an den Resource
   Server geschickt und so weniger leicht kompromitiert werden können.

**Vorteile**

  * Tokens können verlängert werden, Nutzer muss nur einmal bestätigen

**Nachteile**

  * PAIA auth benötigt auch hier eine Benutzeroberfläche
  * Umfangreicher zu Implementieren

## Zusammenfassung

Der [Password Grant] und [Client Credentials Grant] sind zwar am einfachsten
umzusetzen, erfordern aber dass Anwendungen die Zugangsdaten sicher verwalten.
Daher wird vom Einsatz abgeraten sofern die Anwendung nicht unter vollständiger
Kontrolle des Nutzers läuft. Dies trifft auf mobile Endgeräte, im Gegensatz zu
selbst administrierten Computern, strenggenommen nicht zu.

## Anwendungen

### Registrierung von Anwendungen

OAuth 2.0 [fordert eine
Registrierung](https://tools.ietf.org/html/rfc6749#section-2) von Anwendungen,
legt dafür aber kein einheitliches Verfahren fest. Bei OpenID Connect ist
hierfür eine eigene Funktion definiert ([RFC 7591]). Es ist also zu klären,
wie Anwendungen ohne allzu großen administrativen Aufwand registriert werden 
können. Sinnvoll wäre auch ein Verfahren, dass für mehrere PAIA-Server
gleichzeitig funktioniert.

In jedem Fall müssen Anwendungen zunächst am Authorization Server mit
mindestens folgenden Angaben registriert werden:

* Name (z.B. "Benachrichtigungsdienst")
* Logo (optional)
* Homepage-URL (optional)
* Kurzbeschreibung (optional)
* Redirect-URL (z.B. <https://bibapp.de/notify/callback>)

Bei der Registrierung erhält die Anwendung eine eindeutige, nicht geheime
`client_id` und bei Bedarf ein `client_secret`.

### Authentifizierung von Anwendungen

Es wird empfohlen, dass Anwendungen sich bei Anfragen an den Authentification
Server zusätzlich mit ihren `client_id` und `client_secret` per HTTP Basic
authentification ([RFC 2617]) authentifizieren. Zur Not kann auch der Empfang
der beiden Felder im Request body unterstützt werden, dies wird jedoch nicht
empfohlen. Ohne Authentifizierung der Anwendung können sich Angreifer bei
Kenntnis der CLIENT_ID als andere Anwendung ausgeben -- deshalb sollten die
REDIRECT_URL bei Anfragen nicht frei wählbar sondern pro Anwendung festgelegt
sein.

## Weitere Funktionen

### Token Revocation

Zusätzlich sieht OAuth die Möglichkeit vor, das Anwendungen Tokens explizit
als ungültig markieren können. Für den Passwort Grant entspricht dies in etwa
der vorhandenen PAIA auth Methode logout. Im Detail ist diese Methode jedoch
nicht entsprechend der OAUth-Spezifikation umgesetzt (siehe [Issue der
PAIA-Spezifikation](https://github.com/gbv/paia/issues/49)). Da Token
Revocation optional ist, kann zunächst auf die Umsetztung verzichtet werden,
zumal in der Praxis ggf. ausreicht, das Refresh Token zu löschen.

### Authorisierung an anderem Identity Provider

Obgleich es so scheinen mag, dient OAuth selbst *nicht der Authentifizierung
oder Authorisierung* sondern deren Deligierung. In welcher Form der
Authorization Server Nutzer authentifiziert und die gewünschten Berechtigungen
bestätigt ist nicht festgelegt. Grundsätzlich sind Nutzer und Berechtigungen
bei einem Identity Provider (IdP) hinterlegt, der im einfachsten Fall aus einer
Nutzerdatenbank besteht.

Die Abfrage am IdP kann intern erfolgen:


     +---------+                                          +---------------+
     |         |---(1) client_id, redirect_uri & scope -->| Authorization |
     | Browser |---(2) Nutzer meldet sich an ------------>|   Server      |
     |         |<--(3) Authorization Code ----------------|               |
     +---------+                                          +---------------+
       ^   |                                                 | interne ^
       |   v                                                 v Abfrage |
     +--------+                                        +------------------+
     | Client |                                        | Identiy Provider |
     +--------+                                        +------------------+


Es ist aber denkbar, dass der Authorization Server den Nutzer direkt an den IdP
weiterleitet, wo sich dieser die Anfrage bestätigt:

     +---------+                                          +---------------+
     |         |---(1) client_id, redirect_uri & scope -->| Authorization |
     | Browser |<--(3) Authorization Code ----------------|   Server      |
     |         |--\                                       |               |
     +---------+  |                                       +---------------+
       ^   |      |                                          |    ^
       |   |      |                                Redirect (1)  (3) OK + patron
       |   v      |                                          v    | 
     +--------+   |                                    +------------------+
     | Client |   \--(2) Nutzer meldet sich an ------->| Identiy Provider |
     +--------+                                        +------------------+

Hierbei muss jedoch sichergestellt werden dass dem Authorization Server
kein scheinbar vom IdP stammendes gefälschtes "OK" untergeschoben werden kann.

## Beispiel

Als Beispiel wird ein PAIA auth Server mit der Basis-URL
<https://paia.gbv.de/DE-Hil2/auth> und eine Anwendung mit der Basis-URL
<https://bibapp.de/notify/> angenommen.

## Umsetzung

Insgesamt ist OAuth 2.0 sehr komplex, es muss aber nicht in seiner Gänze
umgesetzt werden. Vermutlich ist es am Besten zunächst den Authorization Code
Grant umzusetzen, auch wenn dieses Verfahren das umfangreichste ist.

Damit Nutzer Anwendungen authorisieren können, benötigt der PAIA-Server
zunächst eine **Benutzeroberfläche** mit mindestens den folgenden Funktionen:

* Login am Benutzerkonto (Benutzername & Passwort). Da das Login nur
  für die Benutzeroberfläche des PAIA auth Servers gilt, reicht ein 
  einfaches Cookie, das für den Implicit Grant eine längere Lebensdauer
  haben sollte.

* [Übersicht von authorisierten Anwendungen](oauth-applications.html)

* Bestätigung einzelner Anwendungen
    * z.B. [BibApp](oauth-bibapp.html)
    * z.B. [Benachrichtigungsdienst](oauth-notify.html)
    * z.B. [Campus-Community](oauth-campus.html)

Für den Client Credential Grant käme hinzu:

* Konfiguration eigener Anwendungen
    * z.B. [Finanzskript](oauth-finanz.html)

## Siehe auch

* Eine (noch komplexere) Alternative zu OAuth 2.0 ist SAML (z.B. Shibboleth)

* [Wikipedia zu OpenID Connect](https://en.wikipedia.org/wiki/OpenID_Connect)
* Heise-Artikel zu OpenID Connect: 
  [Teil 1](http://www.heise.de/developer/artikel/OpenID-Connect-Login-mit-OAuth-Teil-1-Grundlagen-2218446.html), [Teil 2](http://www.heise.de/developer/artikel/OpenID-Connect-Login-mit-OAuth-Teil-2-Identity-Federation-und-fortgeschrittene-Themen-2266017.html)


[OAuth 2.0]: http://tools.ietf.org/html/rfc6749
[OpenID Connect]: http://openid.net/connect/
[RFC 7591]: http://tools.ietf.org/html/rfc7591
[RFC 2617]: http://tools.ietf.org/html/rfc2617

