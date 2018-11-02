open System
open System.Diagnostics
open System.Security.Cryptography
let [<Literal>] sshkeygen = @"C:\Program Files\Git\usr\bin\ssh-keygen.exe"
let [<Literal>] openssl = @"C:\Program Files\Git\mingw64\bin\openssl.exe"
let procinfo app args= 
    new ProcessStartInfo(
        app,
        args|>String.concat " ",
        UseShellExecute=false,
        RedirectStandardOutput=true,
        RedirectStandardInput=true,
        RedirectStandardError=true,
        CreateNoWindow =true,
        WorkingDirectory= __SOURCE_DIRECTORY__
    )
let generateKeys (name:string) (pass:string) (c:string)= 
    async {
        if IO.File.Exists(name) && IO.File.Exists(name+".pub") then
            return 1,"you have files"
        else
        //IO.File.Delete(name)
        //IO.File.Delete(name+".pub")
            let pi=
                procinfo sshkeygen [
                    "-f"
                    name
                    "-t"
                    //"ed25519"
                    "rsa"
                    "-b"
                    "4096"
                    "-C"
                    c
                    "-N"
                    pass
                    
                ]
            let p=new Process(StartInfo=pi)
            let s=
                if p.Start() then
                    let s = p.StandardOutput.ReadToEnd()+p.StandardError.ReadToEnd()
                    p.WaitForExit()
                    s
                else
                    p.StandardError.ReadToEnd()
            return (p.ExitCode,s)
    }
let genSessionKeys name c = generateKeys name String.Empty c
let keygenerator issuer=generateKeys (issuer+"/key") "1234567890" "alice@some.net"|>Async.RunSynchronously
let filekeygenerator issuer file=generateKeys (issuer+"/"+file+".key") "1234567890" "alice@some.net"|>Async.RunSynchronously

//openssl rsautl -encrypt -oaep -pubin -inkey <(ssh-keygen -e -f recipients-key.pub -m PKCS8) -in secret.key -out secret.key.enc
let generatePK atype (pubfile:string)= 
    async {
            let pi=
                procinfo sshkeygen [
                    "-e"
                    "-f"
                    pubfile
                    "-m"
                    atype                    
                ]
            let p=new Process(StartInfo=pi)
            let s=
                if p.Start() then
                    let s = p.StandardOutput.ReadToEnd()//+p.StandardError.ReadToEnd()
                    p.WaitForExit()
                    s
                else
                    p.StandardError.ReadToEnd()
            return (p.ExitCode,s)
    }
let generatePKCS8 = generatePK "PKCS8"    
let generatePEM = generatePK "PEM"    
let encrypt name pubfile=
    async {
        let! rc,key=generatePKCS8 pubfile
        if rc<>0 then
            return 1,"cant get PKCS8"
        else
            System.IO.File.WriteAllText(pubfile+".pkcs8",key)
            let pi=
                procinfo openssl [
                    "rsautl"
                    "-encrypt"
                    "-oaep"
                    "-pubin"
                    "-inkey"
                    pubfile+".pkcs8"
                    "-in"
                    name
                    "-out"
                    name+".enc"
                    
                ]
            let p=new Process(StartInfo=pi)
            let s=
                if p.Start() then
                    let s = p.StandardOutput.ReadToEnd()+p.StandardError.ReadToEnd()
                    p.WaitForExit()
                    s
                else
                    p.StandardError.ReadToEnd()
            return (p.ExitCode,s)
    }

let decrypt name prifile (pripass:string)=
//openssl rsautl -decrypt -oaep -inkey ~/.ssh/id_rsa -in secret.key.enc -out secret.key
    async {
            let pi= 
                procinfo openssl
                    [
                        "rsautl"
                        "-decrypt"
                        "-oaep"
                        "-inkey"
                        prifile
                        "-in"
                        name
                        "-out"
                        name+".dec"
                        "-passin"
                        "pass:"+pripass
                    ]
            let p=new Process(StartInfo=pi)
            let s=
                if p.Start() then
                    let s = p.StandardOutput.ReadToEnd()+p.StandardError.ReadToEnd()
                    p.WaitForExit()
                    s
                else
                    p.StandardError.ReadToEnd()
            return (p.ExitCode,s)
    }
let sign prifile pripass name =
//openssl pkeyutl -sign -inkey ~/.ssh/id_rsa -in some-file
    async {
            let pi=
                procinfo openssl [
                    "pkeyutl"
                    "-sign"
                    "-inkey"
                    prifile
                    "-in"
                    name
                    "-out"
                    name+".sig"
                    "-passin"
                    "pass:"+pripass
                ]
            let p=new Process(StartInfo=pi)
            let stdout,stderr=
                if p.Start() then
                    let s = (p.StandardOutput.ReadToEnd()|>System.Text.Encoding.ASCII.GetBytes,p.StandardError.ReadToEnd())
                    p.WaitForExit()
                    s
                else
                    Array.empty,p.StandardError.ReadToEnd()
            return (p.ExitCode,stdout,stderr)
    }
let verify pubfile sigfile name=
//openssl pkeyutl -verify -inkey $PUBLIC_KEY_FILE -sigfile signature-file -in some-file
    async {
        let! rc,key=generatePKCS8 pubfile
        if rc<>0 then
            return 1,String.Empty,"cant get pkcs8"
        else
            System.IO.File.WriteAllText(pubfile+".pkcs8",key)
            let pi=
                procinfo openssl [
                    "pkeyutl"
                    "-verify"
                    "-pubin"
                    "-inkey"
                    pubfile+".pkcs8"
                    "-sigfile"
                    sigfile
                    "-in"
                    name
                ]
            let p=new Process(StartInfo=pi)
            let stdout,stderr=
                if p.Start() then
                    let s = (p.StandardOutput.ReadToEnd(),p.StandardError.ReadToEnd())
                    p.WaitForExit()
                    s
                else
                    String.Empty,p.StandardError.ReadToEnd()
            return (p.ExitCode,stdout,stderr)
    }
let verificationResult = function |(0, _, _)->true|_->false
let testSign() = sign "Alice/key" "1234567890" "Alice/MySecret.doc"|>Async.RunSynchronously
let testVerify()=verify "Alice/key.pub" "Alice/MySecret.doc.sig" "Alice/MySecret.doc"|>Async.RunSynchronously
let testVerifyFalse()=verify "Alice/MySecret.doc.key.pub" "Alice/MySecret.doc.sig" "Alice/MySecret.doc"|>Async.RunSynchronously
//testVerify()|>verificationResult
//testVerifyFalse()|>verificationResult
