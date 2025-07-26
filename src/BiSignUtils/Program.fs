open FSharp.SystemCommandLine
open Commands


[<EntryPoint>]
let main argv =
    rootCommand argv {
        description "Tool for working with keys and signatures for ArmA and DayZ addons."
        inputs Input.context
        helpAction
        addCommand generateCmd
        addCommand signCmd
        addCommand checkCmd
        addCommand checkAllCmd
        addCommand bisign2bikeyCmd
    }
