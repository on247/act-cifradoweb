var express = require('express');
var router = express.Router();
const c=require('constants');
const _sodium = require('libsodium-wrappers');
const fs = require('fs').promises;
const { v4: uuidv4 } = require('uuid');
var multer  = require('multer')
var upload = multer({ dest: 'uploads/' })
const KEY_SIZE=64;

//cbb80da28112facfb10fa7cc02bea6b9d6fe3ee246ffc8710f306167b684375e

let  hexdump = (buf) => {
  return buf.toString('hex');
}
let processFileDecrypt = async (req,file, res) => {
  await _sodium.ready;
  const sodium = _sodium;
  let messages=[];
  console.log(req.body);
  let key="";
  try {
     key=sodium.from_hex(req.body.key); 
  } catch (e) {
    messages.push('Clave invalida')
    console.log(err); 
    return res.render('index',{messages}) 
  }
  let fileBuffer= await fs.readFile(file.path);
  let header_len=sodium.crypto_secretstream_xchacha20poly1305_HEADERBYTES;
  let header = Uint8Array.prototype.slice.call(fileBuffer,0,header_len);
  let encryptedContent = Uint8Array.prototype.slice.call(fileBuffer,header_len);
  let state = sodium.crypto_secretstream_xchacha20poly1305_init_pull(header, key);
  let result = sodium.crypto_secretstream_xchacha20poly1305_pull(state, encryptedContent);
  console.log(result);
  if(result){
    let newFilename=file.originalname.substring(0, file.originalname.length - 8);
    let fileId=uuidv4();
    let fileDir=`${__dirname}/../public/files/${fileId}`;
    let filenameOut=`${__dirname}/../public/files/${fileId}/${newFilename}`;
    let downloadlink=`/files/${fileId}/${newFilename}`;
    try{
      await  fs.mkdir(fileDir,{recursive:true});
      await  fs.writeFile(filenameOut,result.message,{flag:"wx"});
      res.render('index',{messages,downloadlink})
    }
    catch(e){
      messages.push('Error al guardar archivo cifrado')
      console.log(err); 

      res.render('index',{messages}) 
    }
  }   
  else{
    messages.push('Clave invalida')
    console.log(err); 
    return res.render('index',{messages}) 
  }
}

let processFileEncrypt = async (file, res) => {
  await _sodium.ready;
  const sodium = _sodium;
  let messages=[];
  let key = sodium.crypto_secretstream_xchacha20poly1305_keygen();
  messages.push("Clave Privada: "+hexdump(Buffer.from(key)));
  let init = sodium.crypto_secretstream_xchacha20poly1305_init_push(key);
  let [state, header] = [init.state, init.header];
  let fileBuffer= await fs.readFile(file.path);
  let encryptedContent = sodium.crypto_secretstream_xchacha20poly1305_push(state,fileBuffer, null,
    sodium.crypto_secretstream_xchacha20poly1305_TAG_MESSAGE);

  var fileContent = new Uint8Array(header.length + encryptedContent.length);
  fileContent.set(header);
  fileContent.set(encryptedContent, header.length);
  let fileId=uuidv4();
  let fileDir=`${__dirname}/../public/files/${fileId}`;
  let filenameOut=`${__dirname}/../public/files/${fileId}/${file.originalname}.cifrado`;
  let downloadlink=`/files/${fileId}/${file.originalname}.cifrado`;
  try{
    await  fs.mkdir(fileDir,{recursive:true});
    await  fs.writeFile(filenameOut,fileContent,{flag:"wx"});
    res.render('index',{messages,downloadlink})
  }
  catch(e){
    messages.push('Error al guardar archivo cifrado')
    console.log(err); 

    res.render('index',{messages}) 
  }
}

router.get('/', function(req, res, next) {
  res.render('index');
});

router.post('/', upload.single("doc"),function(req, res, next) {
  let error=null;
  if(!req.file) {
    error="No se subio un archivo";
  }
  else{
    if(req.body.submit=="Cifrar"){
      return processFileEncrypt(req.file,res);
    }
    else{
      if(!req.body.key) {
        error="No se ingreso clave privada";
      }
      else{
        return processFileDecrypt(req,req.file,res);
      }
    }
  }
  if(error){
    res.render('index',{error}); 
  }
  else{
    res.render('index'); 
  }
});


module.exports = router;
