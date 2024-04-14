#! /bin/bash

echo
if [ ! -f app/packages/edciowa/texted/.env ]; then
  echo "You must create your '.env' configuration first. See 'env-example'."
  echo
  exit -1
fi


echo "Exporting environment variables from '.env'..."
set -o allexport
source app/packages/edciowa/texted/.env
set +o allexport

echo
echo "Deploying the app..."
doctl serverless deploy app/ --remote-build --verbose-build
echo "Done!"
echo
echo
