require('dotenv').config();
let express = require('express');
let bodyParser = require('body-parser');
let chainLib = require('@blurtfoundation/blurtjs');
let { PrivateKey, PublicKey, Signature } = require('@blurtfoundation/blurtjs/lib/auth/ecc');
const RIPEMD160 = require('ripemd160');
const AWS = require('aws-sdk');
const {RateLimiterMemory} = require('rate-limiter-flexible');
const ipfsClient = require('ipfs-http-client');
const ipfsCluster = require('ipfs-cluster-api');



// Set up blurtjs
chainLib.api.setOptions({
  url: "http://localhost:8091",
  retry: true,
  useAppbaseApi: true,
});


//Connect to local ipfs node
const ipfs = ipfsClient('http://localhost:5001');


// connect to ipfs daemon API server
const cluster = ipfsCluster(); 


// Setup AWS
const s3 = new AWS.S3({
  accessKeyId: process.env.S3_ACCESS_KEY,
  secretAccessKey: process.env.S3_SECRET_KEY,
  region: process.env.S3_REGION,
  endpoint: process.env.S3_ENDPOINT,
  signatureVersion: "v4"
});

// Set up rate limiting
const rate_limit_opts = {
  points: process.env.RATE_LIMIT_POINTS,          // 3 images
  duration: 600, //  everry ten minutes
};
const rateLimiter = new RateLimiterMemory(rate_limit_opts);

let app = express();

const port = process.env.PORT || 7070;        // set our port

hdl_upload_s3 = async (req, res) => {
  try {
    const {username, sig } = req.params;

    // const username = this.session.a;
    if ((username === undefined) || (username === null)) {
      throw new Error("invalid user");
    }

    const jsonBody = req.body;
    // console.log(`jsonBody.data.length=${jsonBody.data.length}`);
    if (jsonBody.data.length > process.env.MAX_JSON_BODY_IN_BYTES) {
      throw new Error("File size too big!");
    }

    // data:image/jpeg;base64,
    let indexData = 0;
    if (jsonBody.data[23] === ',') {
      indexData = 23;
    } else if (jsonBody.data[22] === ',') {
      indexData = 22;
    } else if (jsonBody.data[21] === ',') {
      indexData = 21;
    } else {
      throw new Error("could not find index of [,]")
    }

    let prefix_data = jsonBody.data.substring(0, indexData);
    let base64_data = jsonBody.data.substring(indexData);

    // extract content type
    let file_ext = null;
    if (prefix_data.startsWith('data:image/jpeg;')) file_ext = 'jpeg';
    else if (prefix_data.startsWith('data:image/jpg;')) file_ext = 'jpg';
    else if (prefix_data.startsWith('data:image/png;')) file_ext = 'png';
    else if (prefix_data.startsWith('data:image/gif;')) file_ext = 'gif';
    else throw new Error("invalid content type");

    const content_type = `image/${file_ext}`;

    let buffer = new Buffer(base64_data, 'base64');
    // console.log(`buffer.length=${buffer.length}`);
    if (buffer.length > process.env.MAX_IMAGE_SIZE_IN_BYTES) {
      throw new Error("File size too big!");
    }

    // generate a hash // no longer writing to s3
    //const hash_buffer = (new RIPEMD160().update(buffer).digest('hex'));
    //const s3_file_path = `${username}/${hash_buffer}.${file_ext}`;

    { // verifying sig
      let isValidUsername = chainLib.utils.validateAccountName(username);
      if (isValidUsername) {
        throw new Error("Invalid username");
      }

      let existingAccs = await chainLib.api.getAccountsAsync([username]);
      if (existingAccs.length !== 1) {
        throw new Error('Invalid username.');
      }

      let sign_data = Signature.fromBuffer(new Buffer(sig, 'hex'));
      const sigPubKey = sign_data.recoverPublicKeyFromBuffer(buffer).toString();

      const postingPubKey = existingAccs[0].posting.key_auths[0][0];
      const activePubKey = existingAccs[0].active.key_auths[0][0];
      const ownerPubKey = existingAccs[0].owner.key_auths[0][0];

      switch (sigPubKey) {
        case postingPubKey:
        case activePubKey:
        case ownerPubKey:
          // key matched, do nothing
          break;
        default:
          throw new Error('Invalid key.');
      }

      let is_verified = sign_data.verifyBuffer(buffer, PublicKey.fromString(sigPubKey));
      if (!is_verified) {
        throw new Error('Invalid signature.');
      }
    }

    await rateLimiter.consume(username, 1);

 //   await s3.putObject({
 //     ACL: 'public-read',
 //     Bucket: process.env.S3_BUCKET,
 //     Key: s3_file_path,
 //     Body: buffer,
 //     ContentType: content_type
 //   }).promise();


    const results = ipfs.add(buffer);
    for await (const { cid } of results) {
  // CID (Content IDentifier) uniquely addresses the data
  // and can be used to get it again.
    console.log(cid.toString());

}
   cluster.pin.add(cid.toString(), (err) => {
	err ? console.error(err) : console.log('pin added')
})

    // this.body = JSON.stringify({status: 'ok', message: 'success', data: img_full_path});
    res.json({status: 'ok', message: 'success', data: cid.toString()});
  } catch (e) {
    // console.error('Error in /imageupload api call', this.session.uid, error);
    res.json({status: 'error', message: e.message, data: e});
  }
};



// Configure the exprress server
serverStart = () => {
  app.use(bodyParser.json({type: 'application/json', limit: '10mb'}));

  let router = express.Router();
  router.post('/:username/:sig', hdl_upload_s3);
  router.get('/test_cors', async (req, res) => {
    res.json({status: 'ok', message: 'success', data: null});
  });

  app.use('/', router);

  app.listen(port);
  console.log('serverStart on port ' + port);
};


// Start the express server
serverStart();

module.exports = app;
