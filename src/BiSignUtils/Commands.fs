module Commands
open System.IO
open FSharp.SystemCommandLine

let generateCmd =
    let handler (name: string, length: uint) =
        ()
    
    let name = Input.Argument<string>("name", "The name of the authority")
    let length = Input.Option<uint>(["-l"; "--length"], uint 1024, "The length of private key (in bits)")

    command "generate" {
        description "Generate private key"
        inputs (name, length)
        setHandler handler
    }
