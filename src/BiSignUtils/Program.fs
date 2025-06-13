open System.CommandLine.Invocation
open System.CommandLine.Help
open FSharp.SystemCommandLine
open Commands


[<EntryPoint>]
let main argv =
    let showHelp (ctx: InvocationContext) =
        let hc = HelpContext(ctx.HelpBuilder, ctx.Parser.Configuration.RootCommand, System.Console.Out)
        ctx.HelpBuilder.Write(hc)
        
    let ctx = Input.Context() 
    rootCommand argv {
        description "Tool for working with keys and signatures for ArmA and DayZ addons."
        inputs ctx
        setHandler showHelp
        addCommand generateCmd
    }
