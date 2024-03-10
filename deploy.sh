#! /bin/bash

echo
if [ ! -f app/packages/twilio/twilio/.env ]; then
  echo "You must create your '.env' configuration first. See 'env-example'."
  echo
  exit -1
fi


echo "Exporting environment variables from '.env'..."
set -o allexport
source app/packages/twilio/twilio/.env
set +o allexport

echo
echo "Deploying the app..."
doctl serverless deploy app/
echo "Done!"
echo
echo
