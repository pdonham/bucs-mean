//Based on Amazon's developer code samples
//Setup - Note that AWS recommends using the uuid package
//to generate unique bucket names. We're not here, assuming that
//bu-cs591-sum18 will be unique.

let async = require('async')

let AWS = require('aws-sdk');
AWS.config.loadFromPath('../config/aws-s3-config.json');

//Get a new S3 object
let S3 = new AWS.S3({apiVersion: '2006-03-01'})

//let uuid = require('uuid');

// Create unique bucket name, then create the bucket; if it exists this will
//simply return
let bucketName = 'bu-cs591-sum18';
let createParams = {Bucket: bucketName, Key: 'Ernie', Body: 'This is Ernie'};
let listParams = {
    Bucket: bucketName,
    MaxKeys: 50,
    Prefix: "U1"
};
let item = {Bucket: bucketName, Key: "Ernie"}

// Use a promise since the S3 calls will be async. returned data param has the
//request status and endpoint value if needed
//todo Make bucket creation a one-time event, or just use a bucket value from the AWS console

let createBucket = async function () {
    console.log(`Creating bucket`)
    await        S3.createBucket({Bucket: bucketName})
    return
}


let uploadObject = async function (createParams) {
    console.log(`Loading object`)
    await S3.putObject(createParams).promise()
        .then((data) => {
            return data
        })
}

//Get a list of keys in the bucket. Note that you can specify a prefix
//for the key (the Prefix param), so that if you have U123 and U145, a
//Prefix of 'U1' would return both. I suppose
//this might be useful for seeing if an item already exists, however
//if the goal is to retrieve an object, just retrieve it...if it isn't
//in the bucket, you'll get an error telling you so.

async function getS3ObjectsList(listParams) {
    console.log(`In getS3ObjectsList`)
    await S3.listObjectsV2(listParams).promise()
        .then(function (data) {
            console.log(`Current list:`)
            data.Contents.map((item) => console.log(`${item.Key}`))

        })
}

let getS3Object = async function (item) {
    console.log(`In getS3Object`)
    await S3.getObject(item).promise()
        .then((data) => console.log(`Retrieved ${data.Body}`)
        )
}

createBucket()
    .then(uploadObject(createParams))
    .then(getS3ObjectsList(listParams))
    .then(getS3Object(item))
