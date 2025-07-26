module Commands
open System.IO
open System.Collections.Generic
open FSharp.SystemCommandLine
open FSharp.SystemCommandLine.Input
open BIS.Signatures
open BIS.Signatures.Utils
open Utils

let generateCmd =
    let handler (name: string, length: int) =
        let privateKey = BiPrivateKey.Generate(name, length)
        use output = File.Create($"{name}.biprivatekey")
        privateKey.Write(output)
        
        let publicKey = privateKey.ToPublicKey()
        use output = File.Create($"{name}.bikey")
        publicKey.Write(output)
    
    let name = 
        argument<string> "name"
        |> desc "The name of the authority"
    
    let length = 
        option<int> "--length"
        |> alias "-l"
        |> desc "The length of private key (in bits)"
        |> def 1024

    command "generate" {
        description "Generate private key"
        inputs (name, length)
        setAction handler
    }

let signCmd =
    let handler (keyFile: FileInfo, pbos: FileInfo[]) =
        let key = readPrivateKey keyFile
        let signatures =
            pbos
            |> Seq.filter (fun f -> f.Exists)
            |> Seq.map readPbo
            |> Seq.map (fun pbo -> Signing.Sign(key, BiSignVersion.V3, pbo), pbo)
        for signature, pbo in signatures do
            use signStream = File.Create(SigningUtils.GetSignatureFileName(signature.Name, pbo.FileName))
            signature.Write(signStream)
            printfn $"{pbo.FileName} successfully signed"
            pbo.Dispose()
        0

    let keyFile =
        argument "key"
        |> desc "The path to private key file"
        |> validateFileExists
    let pbos =
        argument<FileInfo[]> "pbo"
        |> desc "The path to PBO to sign"

    command "sign" {
        description "Sign PBO files"
        inputs (keyFile, pbos)
        setAction handler
    }

let checkCmd =
    let handler (keyFile: FileInfo, pbos: FileInfo[]) =
        let key = readPublicKey keyFile
        let loadSignature (fInfo:FileInfo) = 
            if fInfo.Exists then
                let sign = readSign fInfo
                Option.Some sign
            else
                Option.None
        let pbos =
            pbos
            |> Seq.filter (fun f -> f.Exists)
            |> Seq.map (fun f -> f, SigningUtils.GetSignatureFile(key.Name, f))
            |> Seq.map (fun (pboFile, signFile) -> readPbo pboFile, loadSignature signFile)

        for pbo, maybeSign in pbos do
            match maybeSign with
            | Some(signature) -> 
                if Signing.Verify(key, signature, pbo) then
                    printfn $"{pbo.FileName} signature verified sucessfully"
                else 
                    printfn $"{pbo.FileName} signature is wrong"
            | None -> printfn $"{pbo.FileName} is not signed with the authority of ${key.Name}.bikey"
            pbo.Dispose()
        0

    let keyFile = 
        argument "key"
        |> desc "The path to public key file"
        |> validateFileExists
    let pbos =
        argument<FileInfo[]> "pbo"
        |> desc "The path to PBO to sign"

    command "check" {
        description "Check PBO signatures"
        inputs (keyFile, pbos)
        setAction handler
    }

let checkAllCmd = 
    let handler (keysDir: DirectoryInfo, addonDir: DirectoryInfo) =
        let allowedKeys = 
            keysDir.EnumerateFiles("*.bikey")
            |> Seq.map readPublicKey
        let allowedKeys = HashSet(allowedKeys)

        let findSignaturesForPbo (f: FileInfo) = 
            f.Directory.EnumerateFiles($"{f.Name}.*.bisign")
            |> Seq.map readSign 
            |> Seq.toArray

        let pbos =
            addonDir.EnumerateFiles("*.pbo", SearchOption.AllDirectories)
            |> Seq.map (fun f -> readPbo f, findSignaturesForPbo f)

        for pbo, signs in pbos do
            if signs.Length > 0 then
                for sign in signs do
                    if Signing.Verify(allowedKeys, sign, pbo) then
                        printfn $"{pbo.FileName} signature {sign.Name}.bisign verified sucessfully"
                    elif allowedKeys.Contains(sign.PublicKey) then
                        printfn $"{pbo.FileName} signature {sign.Name}.bisign is wrong"
                    else
                        printfn $"Key not found for {sign.Name}.bisign"
            else
                printfn $"No signature found for {pbo.FileName}"

    let  keysDir = 
        argument "keys"
        |> desc "The public keys folder"
        |> validateDirectoryExists
    let  addonDir = 
        argument "addon"
        |> desc "The folder to check for PBOs"
        |> validateDirectoryExists

    command "checkAll" {
        description "Check the signatures of all the PBOs in the folder against the available keys."
        inputs (keysDir, addonDir)
        setAction handler
    }

let bisign2bikeyCmd =
    let handler (signFiles: FileInfo[], searchDir: DirectoryInfo option, outputDir: DirectoryInfo) =
        let searchFiles = 
            searchDir
            |> Option.map (fun dir -> dir.EnumerateFiles("*.bisign", SearchOption.AllDirectories))
            |> Option.defaultWith (fun () -> Seq.empty)
         
        let signatures = 
            signFiles
            |> Seq.filter (fun f -> f.Exists)
            |> Seq.append searchFiles
            |> Seq.map readSign

        let keys =
            signatures
            |> Seq.map (fun sign -> sign.PublicKey)
            |> Seq.distinct

        if not outputDir.Exists then
            outputDir.Create()

        for key in keys do
            let fileName = Path.Combine(outputDir.FullName, $"{key.Name}.bikey")
            use output = File.Create(fileName)
            key.Write(output)

    let signFile = 
        argument<FileInfo[]> "sign"
        |> desc "The path to signature file"
    let searchDir = 
        optionMaybe<DirectoryInfo> "--dir"
        |> alias "-d"
        |> desc "The folder for recursive signature search"
    let outputDir = 
        option "--output"
        |> alias "-o"
        |> desc "The folder for outputting extracted keys."
        |> defaultValue (DirectoryInfo(Directory.GetCurrentDirectory()))

    command "bisign2bikey" {
        description "Generate .bikey from .bisign"
        inputs (signFile, searchDir, outputDir)
        setAction handler
    }
