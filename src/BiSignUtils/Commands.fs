module Commands
open System.IO
open FSharp.SystemCommandLine
open BIS.Signatures

let generateCmd =
    let handler (name: string, length: int) =
        let key = BiPrivateKey.Generate(name, length)
        use output = File.Create($"{name}.biprivatekey")
        key.Write(output)
        ()
    
    let name = Input.Argument<string>("name", "The name of the authority")
    let length = Input.Option<int>(["-l"; "--length"], 1024, "The length of private key (in bits)")

    command "generate" {
        description "Generate private key"
        inputs (name, length)
        setHandler handler
    }
