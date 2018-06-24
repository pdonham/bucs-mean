let AWS = require('aws-sdk');
AWS.config.loadFromPath('../config/aws-s3-config.json');

const lambda = require('aws-lambda-invoke');


let upit = () => {
    lambda.invoke('awsUppercase', 'somestring').then(result => {
        console.log(result);
        //=> '{"foo": "bar"}'
    });
}
upit()

