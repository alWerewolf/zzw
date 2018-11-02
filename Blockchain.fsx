open System.IO
open System.Reflection
open FSharp.Reflection
#r "System.Runtime.Serialization"
#r "System.Runtime.Serialization.Json"
open System
open System.Security.Cryptography
type
    Block = {
        index: uint64
        timestamp: int64
        prevBlockHash: byte []
        hash: byte []
        proof: int
        data: byte []
    }

let calcHash (digest: unit -> HashAlgorithm) = 
    let d =digest()
    fun (input: byte[]) ->d.ComputeHash(input)
let sha256 = calcHash (fun () -> new SHA256Managed() :> HashAlgorithm)

//[0uy..100uy]|>List.map(fun i->sha256 [|i|])
//let sha1 = hashBlock (fun () -> new SHA1Managed() :> HashAlgorithm)
//let ripe160 = hashBlock (fun () -> new RIPEMD160Managed() :> HashAlgorithm)
//let hash160 = sha256 >> ripe160
let dsha = sha256 >> sha256
let hashFunc = dsha//sha256
let proofHashFunc = hashFunc
let [<Literal>] proofValidLen = 2
let timestamp = System.DateTimeOffset.UtcNow.ToUnixTimeMilliseconds
let a2b:string->byte[] = System.Text.Encoding.UTF8.GetBytes
let block data prevBlock proof= 
    let timestamp = timestamp()
    let newIndex = prevBlock.index+1UL
    {
        Block.timestamp = timestamp
        index = newIndex
        proof = proof
        data = data
        prevBlockHash = prevBlock.hash
        hash =
            [ BitConverter.GetBytes(timestamp);BitConverter.GetBytes(newIndex);BitConverter.GetBytes(proof); data; prevBlock.hash ]
            |>Array.concat
            |>hashFunc
            
    }
let validBlockHash (b:Block) =
    [ BitConverter.GetBytes(b.timestamp);BitConverter.GetBytes(b.index); BitConverter.GetBytes(b.proof);b.data; b.prevBlockHash ]
    |>Array.concat
    |>hashFunc
let validProof (lastProof:int) (proof:int) prevHash =
    [BitConverter.GetBytes(lastProof); BitConverter.GetBytes(proof);prevHash]
    |>Array.concat
    |>proofHashFunc
    |>Seq.take proofValidLen
    |>Seq.exists ((<>)30uy)
    |>not
let proofOfWork (lastProof:int) prevHash =
    let proof = ref 0
    while (validProof lastProof !proof prevHash)|> not do
        incr proof
    !proof
let inline proofOfWorkBlock {proof=proof;hash=hash}= proofOfWork proof hash


let blockStr data prevBlockHash=block (data|>a2b) prevBlockHash 
type Chain ={
    blocks: Block list
    current: byte []
    nodes: Uri list
}
let chainHead {blocks=blocks}=blocks|>List.head 
let chain genesis proof =
    {
        blocks=[
            {
                Block.timestamp = 0L
                index = 0UL
                proof=proof
                data = genesis
                prevBlockHash = Array.empty
                hash = sha256 genesis
            }
        ]
        current = Array.empty
        nodes = List.empty
    }
let chainBlock proof chain =
    let ablock = block chain.current chain.blocks.Head proof
    let newChain={chain with blocks=ablock::chain.blocks;current=Array.empty}
    ablock,newChain
type MineMessage ={
    message:string
    index: uint64
    data:byte[]
    proof:int
    prevHash:byte[]
}

let mine chain =
    let proof = chain.blocks |> List.head |> proofOfWorkBlock
    let newBlock,newChain=chainBlock proof chain
    {
        MineMessage.message = "done"
        index = newBlock.index
        data=newBlock.data
        proof=newBlock.proof
        prevHash=newBlock.prevBlockHash
    }
let validateChain {blocks=blocks} =
    blocks
    |>List.rev
    |>List.pairwise 
    |>Seq.exists (fun (prevBlock,block)->
        block.prevBlockHash=prevBlock.hash && block.hash=validBlockHash block && validProof prevBlock.proof block.proof block.prevBlockHash
    )
    |>not
let add data chain= 

    {chain with current=data} |> chainBlock 0 |>snd
let addStr data chain= add (a2b data) chain
let testChain =
    ("Datamart Genesis" |> a2b,100)
    ||> chain
    |> addStr ("data 1")
    |> addStr ("data 2")
let testValidate() = if validateChain testChain then printfn "Validation of chain works" else failwith "Failed to validate chain"
// testValidate()

open System.Runtime.Serialization
open System.Runtime.Serialization.Json
let knownTypes<'T> = 
    typedefof<'T>.GetNestedTypes(BindingFlags.Public ||| BindingFlags.NonPublic) 
    |> Array.filter FSharpType.IsUnion

[<DataContract>]
type RegisterRecord =
    {
        [<field: DataMember>]
        id:string
        [<field: DataMember>]
        pub:string
        [<field: DataMember>]
        data:byte[]
    }
let [<Literal>] Alice = "Alice"
let [<Literal>] AliceEmail = "alice@some.net"
let [<Literal>] Bob = "Bob"
let [<Literal>] BobEmail = "bob@some.net"
#load "Crypto.fsx"
open Crypto
keygenerator Alice
let recordAlice = {
    RegisterRecord.id = AliceEmail
    pub = System.IO.File.ReadAllText (Alice+"/key.pub")
    data = Array.empty
}
keygenerator Bob
let recordBob = {
    RegisterRecord.id = BobEmail
    pub = System.IO.File.ReadAllText (Bob+"/key.pub")
    data = Array.empty
}

let serializeRecord<'T>=
    let ser = DataContractJsonSerializer(typeof<'T>)
    fun (record:'T)->
        let s= new MemoryStream()
        ser.WriteObject(s,box record)
        s.ToArray()
let deserializeRecord<'T> =
    let ser = DataContractJsonSerializer(typeof<'T>)
    fun (buffer:byte[]) ->
        let s=new MemoryStream(buffer)
        ser.ReadObject(s)|>unbox<'T>
let mutable pubChain =
    ("Datamart Genesis public" |> a2b,100)
    ||> chain
    |> add (serializeRecord<RegisterRecord> recordAlice)
    |> add (serializeRecord<RegisterRecord> recordBob)


let chainIndex chooser chain= chain.blocks|>Seq.takeWhile(fun b->b.index>0UL)|>Seq.choose chooser|>Map.ofSeq
let mutable emailIndex = 
    chainIndex (fun b->
        try
            match b.data|>deserializeRecord<RegisterRecord> with 
            |v->Some (v.id,b)
            |_->None
        with 
        |_->None) pubChain
let mutable hashIndex = chainIndex (fun b->Some (b.hash,b)) pubChain
let testValidatePub() = if validateChain pubChain then printfn "Validation of chain works" else failwith "Failed to validate chain"
// testValidatePub()
let [<Literal>] AlicesDoc = "MySecret.doc"
let AliceDocMekelRoot = System.IO.File.ReadAllBytes (Alice+"/"+AlicesDoc) |> sha256
filekeygenerator Alice AlicesDoc

//generatePKCS8 (Alice+"/"+AlicesDoc+".key.pub")|>Async.RunSynchronously
encrypt (Alice+"/"+AlicesDoc) (Alice+"/"+AlicesDoc+".key.pub")|>Async.RunSynchronously
//decrypt (Alice+"/"+AlicesDoc+".enc") (Alice+"/"+AlicesDoc+".key") "1234567890"|>Async.RunSynchronously
[<DataContract>]
type FileInfoBlock = {
    [<field: DataMember>]
    owner: byte []
    [<field: DataMember>]
    MerkelRoot: byte []
    [<field: DataMember>]
    description: byte []
    [<field: DataMember>]
    fv: byte []->byte []
    [<field: DataMember>]
    cost: uint64
}
let mutable docIndex = 
    chainIndex (fun b->
        try
            match b.data|>deserializeRecord<FileInfoBlock> with 
            |v->Some (v.MerkelRoot,b)
            |_->None
        with
        |_->None) pubChain
let recordAliceDoc = {
    owner = emailIndex.[AliceEmail].hash
    MerkelRoot = AliceDocMekelRoot
    description = a2b "Alice file description"
    fv = sha256
    cost = 175UL
}

pubChain <- pubChain|> add (serializeRecord<FileInfoBlock> recordAliceDoc)
// testValidatePub()

[<KnownType("GetKnownTypes")>]
type ContractState= 
    |BuyerRequest |SellerMerkleRoot |BuyerPubDeposit |SellerGarantDeposit |DownCompleteKeyRequest |SellerPrivKey |Fail |Valid
    static member GetKnownTypes() = knownTypes<ContractState>

[<DataContract>]
type ContractBlock = {
    [<field: DataMember>]
    owner: byte []
    [<field: DataMember>]
    requestor: byte []
    [<field: DataMember>]
    resource: byte []
    [<field: DataMember>]
    state: ContractState
    [<field: DataMember>]
    data: byte []
}
let recordBobRequestAliceFile = {
    ContractBlock.owner = emailIndex.[AliceEmail].hash
    requestor = emailIndex.[BobEmail].hash
    resource = docIndex.[AliceDocMekelRoot].hash
    state = BuyerRequest
    data = "sha256" |>a2b // validation funk
}
genSessionKeys (Alice+"/"+Alice+"2"+Bob+".sess.key") AliceEmail
encrypt (Alice+"/"+AlicesDoc+".key") (Alice+"/"+Alice+"2"+Bob+".sess.key.pub")|>Async.RunSynchronously

let AliceDocKeyMekelRoot = System.IO.File.ReadAllBytes (Alice+"/"+AlicesDoc+".key.enc") |> sha256
let recordAliceReportRoot = {
    ContractBlock.owner = emailIndex.[AliceEmail].hash
    requestor = emailIndex.[BobEmail].hash
    resource = docIndex.[AliceDocMekelRoot].hash
    state = SellerMerkleRoot
    data = AliceDocKeyMekelRoot
}
genSessionKeys (Bob+"/"+Bob+"2"+Alice+".sess.key") BobEmail
let recordBobReportPublicKey = {
    ContractBlock.owner = emailIndex.[AliceEmail].hash
    requestor = emailIndex.[BobEmail].hash
    resource = docIndex.[AliceDocMekelRoot].hash
    state = BuyerPubDeposit
    data = [[|175uy|];System.IO.File.ReadAllBytes (Bob+"/"+Bob+"2"+Alice+".sess.key")] |>Array.concat//buyer session public key and qty
}
let recordAliceGuarantieDeposit = {
    ContractBlock.owner = emailIndex.[AliceEmail].hash
    requestor = emailIndex.[BobEmail].hash
    resource = docIndex.[AliceDocMekelRoot].hash
    state = SellerGarantDeposit
    data = Array.singleton 175uy //qty
}
//transfer fs
let recordBobDownloadFinished = {
    ContractBlock.owner = emailIndex.[AliceEmail].hash
    requestor = emailIndex.[BobEmail].hash
    resource = docIndex.[AliceDocMekelRoot].hash
    state = DownCompleteKeyRequest
    data = Array.empty //qty
}
encrypt (Alice+"/"+Alice+"2"+Bob+".sess.key") (Bob+"/"+Bob+"2"+Alice+".sess.key.pub")|>Async.RunSynchronously

let recordAliceSendEncKey = {
    ContractBlock.owner = emailIndex.[AliceEmail].hash
    requestor = emailIndex.[BobEmail].hash
    resource = docIndex.[AliceDocMekelRoot].hash
    state = SellerPrivKey
    data = System.IO.File.ReadAllBytes (Alice+"/"+Alice+"2"+Bob+".sess.key.enc") //qty
}

let recordBobCorruptData = {
    ContractBlock.owner = emailIndex.[AliceEmail].hash
    requestor = emailIndex.[BobEmail].hash
    resource = docIndex.[AliceDocMekelRoot].hash
    state = Fail
    data = Array.empty //Alice private key || chunk ||MerklePath -> if approved B get Guarantee and self deposit
}

let recordBobDataOk = {
    ContractBlock.owner = emailIndex.[AliceEmail].hash
    requestor = emailIndex.[BobEmail].hash
    resource = docIndex.[AliceDocMekelRoot].hash
    state = Valid
    data = Array.empty // if approved A get Guarantee and B deposit
}
pubChain <- 
    pubChain
    |> add (serializeRecord<ContractBlock> recordBobRequestAliceFile)
    |> add (serializeRecord<ContractBlock> recordAliceReportRoot)
    |> add (serializeRecord<ContractBlock> recordBobReportPublicKey)
    |> add (serializeRecord<ContractBlock> recordAliceGuarantieDeposit)
    |> add (serializeRecord<ContractBlock> recordBobDownloadFinished)
    |> add (serializeRecord<ContractBlock> recordAliceSendEncKey)
System.IO.File.Copy(Alice+"/"+AlicesDoc+".enc",Bob+"/"+AlicesDoc+".enc")
System.IO.File.Copy(Alice+"/"+Alice+"2"+Bob+".sess.key.enc",Bob+"/"+Alice+"2"+Bob+".sess.key.enc")
System.IO.File.Copy(Alice+"/"+AlicesDoc+".key.enc",Bob+"/"+AlicesDoc+".key.enc")
decrypt (Bob+"/"+Alice+"2"+Bob+".sess.key.enc") (Bob+"/"+AlicesDoc+".sess.key") ""|>Async.RunSynchronously
let NoShort = System.IO.File.ReadAllBytes (Bob+"/"+Alice+"2"+Bob+".sess.key") |> sha256 <> AliceDocKeyMekelRoot
decrypt (Bob+"/"+AlicesDoc+".key.enc") (Bob+"/"+Alice+"2"+Bob+".sess.key.enc") ""|>Async.RunSynchronously
let noLong = System.IO.File.ReadAllBytes (Alice+"/"+AlicesDoc+".key.pub")
let caseNoShort =
    pubChain
    |> add (serializeRecord<ContractBlock> recordBobCorruptData)
let caseNoLong =
    pubChain
    |> add (serializeRecord<ContractBlock> recordBobCorruptData)
decrypt (Bob+"/"+AlicesDoc+".enc") (Bob+"/"+AlicesDoc+".key") "1234567890"|>Async.RunSynchronously
let isOk = System.IO.File.ReadAllBytes (Bob+"/"+AlicesDoc) |> sha256 <> AliceDocMekelRoot
let caseOk =
    pubChain
    |> add (serializeRecord<ContractBlock> recordBobDataOk)
    
// testValidatePub()
module Readable =
    
    type RBlock<'T> = {
        index: uint64
        timestamp: DateTime
        prevBlockHash: string
        hash: string
        proof: int
        data: 'T
    }
    let  block(block:Block) = {
        RBlock.index = block.index
        timestamp = DateTimeOffset.FromUnixTimeMilliseconds(block.timestamp).LocalDateTime
        prevBlockHash = block.prevBlockHash|>Convert.ToBase64String
        hash = block.hash|>Convert.ToBase64String
        proof = block.proof
        data = block.data|>Text.Encoding.UTF8.GetString
    }
    let registerRecord (block:Block) =
        {
            RBlock.index = block.index
            timestamp = DateTimeOffset.FromUnixTimeMilliseconds(block.timestamp).LocalDateTime
            prevBlockHash = block.prevBlockHash|>Convert.ToBase64String
            hash = block.hash|>Convert.ToBase64String
            proof = block.proof
            data = block.data|>deserializeRecord<RegisterRecord>
        }
let testPrintBlock() = testChain.blocks.Head|>Readable.block|> printfn "%A"
let testPrintRegisterRecord() = pubChain.blocks.Head|>Readable.registerRecord|> printfn "%A"
let testPrintAllRegisterRecord() = pubChain.blocks|>List.takeWhile (fun a->a.index>0UL)|>List.map (Readable.registerRecord>> sprintf "%A")
//testPrintBlock()
//testPrintRegisterRecord()


