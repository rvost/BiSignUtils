module Utils

open System.IO
open BIS.Signatures
open BIS.PBO

let private parseFile (reader:(Stream -> 'a)) (f:FileInfo)  : 'a =
    use input = f.OpenRead()
    let result = reader input
    result

let readPublicKey (f:FileInfo) = parseFile BiPublicKey.Read f

let readPrivateKey (f:FileInfo) = parseFile BiPrivateKey.Read f

let readSign (f:FileInfo) = parseFile BiSign.Read f

let readPbo (f:FileInfo) =
    new PBO(f.FullName, false)