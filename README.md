production: https://voldis.herokuapp.com/<br>
staging: https://voldis-staging.herokuapp.com/


For starting project:
* Create file ```config/application.yml``` from ```config/applicatiopn.yml.sample``` with required cofigurations
* Run ```bundle install``` for installing gems
* ```rake db:create db:migrate db:seed``` for creating database and filling it with sample data
* ```rails s``` for starting local server
* Enjoy!

//in progress
Each pull request is automatically deploying to heroku, migrations and seeding start automatically too.
