DB_SERVER_HERE/* jshint node: true, devel: true */
'use strict';

const
  bodyParser = require('body-parser'),
  config = require('config'),
  crypto = require('crypto'),
  express = require('express'),
  https = require('https'),
  request = require('request'),
  mongo = require('mongodb').MongoClient;

var app = express();
app.set('port', process.env.PORT || 5000);
app.set('view engine', 'ejs');
app.use(bodyParser.json({ verify: verifyRequestSignature }));
app.use(express.static('public'));



// App Secret can be retrieved from the App Dashboard
const APP_SECRET = (process.env.MESSENGER_APP_SECRET) ?
  process.env.MESSENGER_APP_SECRET :
  config.get('appSecret');

// Arbitrary value used to validate a webhook
const VALIDATION_TOKEN = (process.env.MESSENGER_VALIDATION_TOKEN) ?
  (process.env.MESSENGER_VALIDATION_TOKEN) :
  config.get('validationToken');

// Generate a page access token for your page from the App Dashboard
const PAGE_ACCESS_TOKEN = (process.env.MESSENGER_PAGE_ACCESS_TOKEN) ?
  (process.env.MESSENGER_PAGE_ACCESS_TOKEN) :
  config.get('pageAccessToken');

// URL where the app is running (include protocol). Used to point to scripts and
// assets located at this address.
const SERVER_URL = (process.env.SERVER_URL) ?
  (process.env.SERVER_URL) :
  config.get('serverURL');

if (!(APP_SECRET && VALIDATION_TOKEN && PAGE_ACCESS_TOKEN && SERVER_URL)) {
  console.error("Missing config values");
  process.exit(1);
}

var sorry = "Sorry, something went wrong!";

//Code to check that the server and reverse proxy is working
app.get('/BeloteBot/', function(req, res) {
  res.status(200).send("Success");
  console.log(" / Get request received");
});


/*
 * Use your own validation token. Check that the token used in the Webhook
 * setup is the same token used here.
 *
 */
app.get('/BeloteBot/webhook', function(req, res) {
  if (req.query['hub.mode'] === 'subscribe' &&
      req.query['hub.verify_token'] === VALIDATION_TOKEN) {
    console.log("Validating webhook");
    res.status(200).send(req.query['hub.challenge']);
  } else {
    console.error("Failed validation. Make sure the validation tokens match.");
    res.sendStatus(403);
  }
});


/*
 * All callbacks for Messenger are POST-ed. They will be sent to the same
 * webhook. Be sure to subscribe your app to your page to receive callbacks
 * for your page.
 * https://developers.facebook.com/docs/messenger-platform/product-overview/setup#subscribe_app
 *
 */
app.post('/BeloteBot/webhook', function (req, res) {
  var data = req.body;

  // Make sure this is a page subscription
  if (data.object == 'page') {
    // Iterate over each entry
    // There may be multiple if batched
    data.entry.forEach(function(pageEntry) {
      var pageID = pageEntry.id;
      var timeOfEvent = pageEntry.time;

      // Iterate over each messaging event
      pageEntry.messaging.forEach(function(messagingEvent) {
        if (messagingEvent.optin) {
          receivedAuthentication(messagingEvent);
        } else if (messagingEvent.message) {
          receivedMessage(messagingEvent);
        }  else if (messagingEvent.postback) {
          postbackHandler(messagingEvent);
        }  else {
          console.log("Webhook received unknown messagingEvent: ", messagingEvent);
        }
      });
    });

    // Assume all went well.
    //
    // You must send back a 200, within 20 seconds, to let us know you've
    // successfully received the callback. Otherwise, the request will time out.
    res.sendStatus(200);
  }
});

/*
 * This path is used for account linking. The account linking call-to-action
 * (sendAccountLinking) is pointed to this URL.
 *
 */
app.get('/BeloteBot/authorize', function(req, res) {
  var accountLinkingToken = req.query.account_linking_token;
  var redirectURI = req.query.redirect_uri;

  // Authorization Code should be generated per user by the developer. This will
  // be passed to the Account Linking callback.
  var authCode = "1234567891011";

  // Redirect users to this URI on successful login
  var redirectURISuccess = redirectURI + "&authorization_code=" + authCode;

  res.render('authorize', {
    accountLinkingToken: accountLinkingToken,
    redirectURI: redirectURI,
    redirectURISuccess: redirectURISuccess
  });
});

/*
 * Verify that the callback came from Facebook. Using the App Secret from
 * the App Dashboard, we can verify the signature that is sent with each
 * callback in the x-hub-signature field, located in the header.
 *
 * https://developers.facebook.com/docs/graph-api/webhooks#setup
 *
 */
function verifyRequestSignature(req, res, buf) {
  var signature = req.headers["x-hub-signature"];

  if (!signature) {
    // For testing, let's log an error. In production, you should throw an
    // error.
    console.error("Couldn't validate the signature.");
  } else {
    var elements = signature.split('=');
    var method = elements[0];
    var signatureHash = elements[1];

    var expectedHash = crypto.createHmac('sha1', APP_SECRET)
                        .update(buf)
                        .digest('hex');

    if (signatureHash != expectedHash) {
      throw new Error("Couldn't validate the request signature.");
    }
  }
}

/*
 * Authorization Event
 *
 * The value for 'optin.ref' is defined in the entry point. For the "Send to
 * Messenger" plugin, it is the 'data-ref' field. Read more at
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference/authentication
 *
 */
function receivedAuthentication(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfAuth = event.timestamp;

  // The 'ref' field is set in the 'Send to Messenger' plugin, in the 'data-ref'
  // The developer can set this to an arbitrary value to associate the
  // authentication callback with the 'Send to Messenger' click event. This is
  // a way to do account linking when the user clicks the 'Send to Messenger'
  // plugin.
  var passThroughParam = event.optin.ref;

  console.log("Received authentication for user %d and page %d with pass " +
    "through param '%s' at %d", senderID, recipientID, passThroughParam,
    timeOfAuth);

  // When an authentication is received, we'll send a message back to the sender
  // to let them know it was successful.
  sendTextMessage(senderID, "Authentication successful");
}

/*
 * Message Event
 *
 * This event is called when a message is sent to your page. The 'message'
 * object format can vary depending on the kind of message that was received.
 * Read more at https://developers.facebook.com/docs/messenger-platform/webhook-reference/message-received
 *
 * For this example, we're going to echo any text that we get. If we get some
 * special keywords ('button', 'generic', 'receipt'), then we'll send back
 * examples of those bubbles to illustrate the special message bubbles we've
 * created. If we receive a message with an attachment (image, video, audio),
 * then we'll simply confirm that we've received the attachment.
 *
 */
function receivedMessage(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfMessage = event.timestamp;
  var message = event.message;

  console.log("Received message for user %d and page %d at %d with message:",
    senderID, recipientID, timeOfMessage);
  console.log(JSON.stringify(message));

  var messageId = message.mid;
  var appId = message.app_id;
  var metadata = message.metadata;


    var messageText = message.text;


  if (messageText) {

      if (containsKeyWord(messageText,'reset')){
          checkIfExistingUser(senderID);
          resetGame(senderID);
      }else if (/^([0-9]*( |-| - | -|- )[0-9]*)$/.test(messageText)) {
        var scoreString = messageText.split('-');
        if (scoreString.length !== 2 || Number(scoreString[0]) == NaN || Number(scoreString[1]) == NaN){
        }else{
            checkIfExistingUser(senderID);
            updateScore(senderID,[Number(scoreString[0]),Number(scoreString[1])]);
          }
      } else if(containsKeyWord(messageText,'hello')){
          newUserButtons(senderID);
      }else if(containsKeyWord(messageText,'help')){
          sendLocalisedMessage(senderID,'commands');
      }else {
          sendLocalisedButtons(senderID,"help");
      }
   }
}

function containsKeyWord(message, keyword) {
    for (var keyWord in keyWords[keyword]){
        console.log(keyWord);
        if (message.toLowerCase().indexOf(keyWords[keyword][keyWord]) !== -1){
            return 1;
        }
    }

}

function newUserButtons(recipientId) {
    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            attachment: {
                type: "template",
                payload: {
                    template_type: "button",
                    text: locale.en.welcomeMsg,
                    buttons:[{
                        type: "postback",
                        title: "English",
                        payload: "EN"
                    }, {
                        type: "postback",
                        title: "Български",
                        payload: "BG"
                    }]
                }
            }
        }
    };
    callSendAPI(messageData);
}

function failedParsingButtons(recipientId,locale) {
    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            attachment: {
                type: "template",
                payload: {
                    template_type: "button",
                    text: locale.failedParsing,
                    buttons:[{
                        type: "postback",
                        title: locale.help,
                        payload: "HELP"
                    }]
                }
            }
        }
    };
    callSendAPI(messageData);
}

function endOfGameButton(recipientId,locale) {
    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            attachment: {
                type: "template",
                payload: {
                    template_type: "button",
                    text: locale.endOfGame,
                    buttons:[{
                        type: "postback",
                        title: locale.endAndRestart,
                        payload: "END"
                    }, {
                        type: "postback",
                        title: locale.keepPlaying,
                        payload: "KEEP_GOING"
                    }]
                }
            }
        }
    };
    callSendAPI(messageData);
}

function sendLocalisedButtons(senderID, buttonsCode) {
    mongo.connect("mongodb://DB_SERVER_HERE/BeloteBot", function (err, db) {
        if (err) {
            sendLocalisedMessage(senderID, 'sorry');
            return;
        }
        var collection = db.collection('userGames');

        collection.findOne({'senderID': senderID}, function (err, item) {
            if (err) {
                sendLocalisedMessage(senderID, 'sorry');
                return;
            } else {
                if (item !== null) {
                    if (item.lang === 'EN') {
                        if(buttonsCode === "end_game"){
                            endOfGameButton(senderID,locale.en);
                        }else {
                            failedParsingButtons(senderID,locale.en);
                        }
                    } else {
                        if(buttonsCode === "end_game"){
                            endOfGameButton(senderID,locale.bg);
                        }else {
                            failedParsingButtons(senderID,locale.bg);
                        }
                    }
                }
            }
        });

    });
}

function resetGame(recipientId) {
    mongo.connect("mongodb://DB_SERVER_HERE/BeloteBot", function(err, db) {
        if(err) {
            sendLocalisedMessage(recipientId, 'sorry');
            return;
        }

        var collection = db.collection('userGames');

        collection.findOne( { 'senderID': recipientId}, function(err, item) {
            if(err) {
                sendLocalisedMessage(recipientId, 'sorry');
                return;
            } else{
                if (item === null){
                   newUserButtons(recipientId);
                }else{
                    collection.update( {'senderID': recipientId }, { $set:{
                        'team1': 0,
                        'team2': 0}}, function(err, result) {
                        if(err) {
                            sendLocalisedMessage(recipientId, 'sorry');
                        } else{
                            sendLocalisedMessage(recipientId,'newGame');
                        }
                    } );
                }
            }
        } );

    });

}

function checkIfExistingUser(senderID) {
    mongo.connect("mongodb://DB_SERVER_HERE/BeloteBot", function (err, db) {
        if (err) {
            sendLocalisedMessage(senderID, 'sorry');
            return;
        }

        var collection = db.collection('userGames');

        collection.findOne({'senderID': senderID}, function (err, item) {
            if (err) {
                sendLocalisedMessage(senderID, 'sorry');
                return;
            } else {
                if (item === null) {
                    newUserButtons(senderID);
                    return 0;
                } else {
                    return 1;
                }

            }
        });

    });
}

function updateScore(senderID,scores) {
    mongo.connect("mongodb://DB_SERVER_HERE/BeloteBot", function(err, db) {
        if(err) {
            sendLocalisedMessage(senderID, 'sorry');
            return;
        }

        var collection = db.collection('userGames');

        collection.update( {'senderID': senderID }, {$inc: {
            team1: scores[0],
            team2:scores[1]}}, function(err, result) {
            if(err) {
                sendLocalisedMessage(senderID, 'sorry');
                return;
            } else{
                collection.findOne( { 'senderID': senderID}, function(err, item) {
                    if(err) {
                        sendLocalisedMessage(senderID, 'sorry');
                        return;
                    } else{
                        if (item !== null){
                            // if (Math.abs(scores[0]-scores[1]) > 10) {
                            //     sendLocalisedMessage(senderID, 'ouch');
                            // }
                            sendLocalisedMessage(senderID, 'currScore', item.team1 + '-' + item.team2);
                            if (item.team1 >= 151 || item.team2 >= 151) {
                               sendLocalisedButtons(senderID,"end_game");
                            }
                        }

                    }
                } );
            }
        } );
    });
}

function postbackHandler(event) {
    var senderID = event.sender.id;
    var recipientID = event.recipient.id;
    var timeOfPostback = event.timestamp;

    // The 'payload' param is a developer-defined field which is set in a postback
    // button for Structured Messages.
    var payload = event.postback.payload;

    if (payload === "END"){
        resetGame(senderID);
        return;
    }
    if (payload === "KEEP_GOING"){
        sendTextMessage(senderID, "OK");
        return;
    }
    if (payload === "EN"){
        createUserInDb(senderID,"EN");
        return;
    }
    if (payload === "BG"){
        createUserInDb(senderID,"BG");
        return;
    }
    if (payload === "HELP"){
        sendLocalisedMessage(senderID,'commands');
    }

}

function createUserInDb(senderID,lang) {
    mongo.connect("mongodb://DB_SERVER_HERE/BeloteBot", function(err, db) {
        if (err) {
            sendLocalisedMessage(senderID, 'sorry');
            return;
        }
        var collection = db.collection('userGames');
        collection.findOne( { 'senderID': senderID}, function(err, item) {
            if(err) {
                sendLocalisedMessage(senderID, 'sorry');
                return;
            } else {
                if (item === null) {
                    collection.insert({
                        'senderID': senderID,
                        'lang': lang,
                        'team1': 0,
                        'team2': 0
                    }, function (err, result) {
                        sendLocalisedMessage(senderID,'commands');
                        sendLocalisedMessage(senderID, "everythingSet");
                        resetGame(senderID);
                    });
                }else{
                    collection.update({'senderID': senderID }, {$set:{
                        'lang': lang
                    }}, function (err, result) {
                        sendLocalisedMessage(senderID, "everythingSet");
                        resetGame(senderID);
                    });

                }
            }
        });
    } );
}

function sendMessageLocaleKnown(recipientId, messageCode, locale, addition) {
    var text = locale[messageCode];
    if (addition) {
        text += addition;
    }
    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            text: text,
            metadata: "DEVELOPER_DEFINED_METADATA"
        }
    };

    callSendAPI(messageData);
}
function sendTextMessage(recipientId, messageText) {

    var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: messageText,
      metadata: "DEVELOPER_DEFINED_METADATA"
    }
    };

      callSendAPI(messageData);
}

function sendTextMessageWithCallback(recipientId, messageText, callback) {
    var messageData = {
        recipient: {
            id: recipientId
        },
        message: {
            text: messageText,
            metadata: "DEVELOPER_DEFINED_METADATA"
        }
    };

    callSendAPI(messageData);
    callback();
}


function callSendAPI(messageData) {
  request({
    uri: 'https://graph.facebook.com/v2.6/me/messages',
    qs: { access_token: PAGE_ACCESS_TOKEN },
    method: 'POST',
    json: messageData

  }, function (error, response, body) {
    if (!error && response.statusCode === 200) {
      var recipientId = body.recipient_id;
      var messageId = body.message_id;

      if (messageId) {
        console.log("Successfully sent message with id %s to recipient %s",
          messageId, recipientId);
      } else {
      console.log("Successfully called Send API for recipient %s",
        recipientId);
      }
    } else {
      console.error("Failed calling Send API", response.statusCode, response.statusMessage, body.error);
    }
  });
}

var locale = {
    en: {
        sorry: "Sorry, something went wrong!",
        currScore: "Current score: ",
        welcomeMsg: "Welcome! What is your preferred language?\nЗдравей, кой език предпочиташ?",
        newGame: "New game is starting. Supply the score updates in the format {Team 1 points}-{Team 2 points}! \n Current score: 0-0",
        everythingSet: "Everything set! Lets play!",
        ouch: "Ouch...",
        endOfGame: "Is this the end of the game?",
        endAndRestart: "End and restart",
        keepPlaying: "Keep playing",
        help: "Help me!",
        failedParsing: "Sorry, but I couldn't understand you! Click help to see what I understand!",
        commands: 'Here are some words I know:\n"New game" or "Restart" will start a new game\n"Hello" open the setup dialog\n"Help" will show the list with commands'
    },
    bg: {
        sorry: "Съжалявам, но нещо се обърка! :(",
        currScore: "Текущ резултат: ",
        newGame: "Започва нова игра! Очаквам резултатите в следия формат {Отбор 1}-{Отбор 2}\n Текущ резултат: 0-0",
        everythingSet: "Всичко е готово! Хайде да играем!",
        ouch: "Оп...",
        endOfGame: "Играта свърши ли?",
        endAndRestart: "Да, започни нова!",
        keepPlaying: "Не, продължава!",
        help: "Помогни ми",
        failedParsing: "Съжалявам но не те разбрах. Натисни 'Помогни ми' за лист с команди!",
        commands: 'Ето някои думи които разбирам:\n"Нова игра" или "Рестарт" ще активират нова игра\n"Здравей" ще отвори диалога за настройки\n"Помощ" ще покаже лист с команди'
    }
};

var keyWords = {
    reset: ["reset", "restart", "new game", "нова игра", "рестарт"],
    hello: ["hello", "hi", "здрасти", "здравей", "добър ден"],
    help: ["help", "помощ", "помогни ми"]
};

function sendLocalisedMessage(senderID, messageCode, addition) {
    mongo.connect("mongodb://DB_SERVER_HERE/BeloteBot", function (err, db) {
        if (err) {
            sendLocalisedMessage(senderID, 'sorry');
            return;
        }
        var collection = db.collection('userGames');

        collection.findOne({'senderID': senderID}, function (err, item) {
            if (err) {
                sendLocalisedMessage(senderID, 'sorry');
                return;
            } else {
                if (item !== null) {
                    if (item.lang === 'EN') {
                        sendMessageLocaleKnown(senderID,messageCode, locale.en, addition);
                    } else {
                        sendMessageLocaleKnown(senderID,messageCode, locale.bg, addition);
                    }
                }
            }
        });

    });
}

function sendLocalisedMessageCallback(senderID, messageCode, callback) {
    mongo.connect("mongodb://DB_SERVER_HERE/BeloteBot", function (err, db) {
        if (err) {
            sendLocalisedMessage(senderID, 'sorry');
            return;
        }
        var collection = db.collection('userGames');

        collection.findOne({'senderID': senderID}, function (err, item) {
            if (err) {
                sendLocalisedMessage(senderID, 'sorry');
                return;
            } else {
                if (item !== null) {
                    if (item.lang === 'EN') {
                        sendTextMessageWithCallback(senderID,messageCode, locale.en, callback);
                    } else {
                        sendTextMessageWithCallback(senderID,messageCode, locale.bg, callback);
                    }
                }
            }
        });

    });
}
// Start server
// Webhooks must be available via SSL with a certificate signed by a valid
// certificate authority.
app.listen(app.get('port'), function() {
  console.log('Node app is running on port', app.get('port'));
});

module.exports = app;
