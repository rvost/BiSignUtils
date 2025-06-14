module Commands
open System.IO
open FSharp.SystemCommandLine
open BIS.PBO
open BIS.Signatures
open BIS.Signatures.Utils

let generateCmd =
    let handler (name: string, length: int) =
        let privateKey = BiPrivateKey.Generate(name, length)
        use output = File.Create($"{name}.biprivatekey")
        privateKey.Write(output)
        let publicKey = privateKey.ToPublicKey()
        use output = File.Create($"{name}.bikey")
        publicKey.Write(output)
    
    let name = Input.Argument<string>("name", "The name of the authority")
    let length = Input.Option<int>(["-l"; "--length"], 1024, "The length of private key (in bits)")

    command "generate" {
        description "Generate private key"
        inputs (name, length)
        setHandler handler
    }

let signCmd =
    let handler (keyFile: FileInfo, pbos: FileInfo[]) =
        if keyFile.Exists then 
            use keyStream = keyFile.OpenRead()
            let key = BiPrivateKey.Read(keyStream)
            let signatures =
                pbos
                |> Seq.filter (fun f -> f.Exists)
                |> Seq.map (fun f -> new PBO(f.FullName, false))
                |> Seq.map (fun pbo -> Signing.Sign(key, BiSignVersion.V3, pbo), pbo)
            for signature, pbo in signatures do
                use signStream = File.Create(SigningUtils.GetSignatureFileName(signature.Name, pbo.FileName))
                signature.Write(signStream)
                printfn $"{pbo.FileName} successfully signed"
                pbo.Dispose()
            0
        else 
            printfn $"Key {keyFile.FullName} does not exist"
            -1

    let keyFile = Input.Argument<FileInfo>("key", "The path to private key file")
    let pbos = Input.Argument<FileInfo[]>("pbo", "The path to PBO to sign")

    command "sign" {
        description "Sign PBO files"
        inputs(keyFile, pbos)
        setHandler handler
    }
