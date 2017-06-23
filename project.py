from flask import Flask, render_template, request, redirect, jsonify, url_for, flash
from sqlalchemy import create_engine, asc
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Restaurant, MenuItem, User

##Importing modules to implement antiforgery state tokens
from flask import session as login_session
import random
import string

##Importing modules for GConnect routing
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)

##Extracting the client_id form the json stored in client_secrets file
CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Restaurant Menu Application"


# Connect to Database and create database session
engine = create_engine('sqlite:///restaurantmenuwithusers.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


##Creating a routing path for login
@app.route('/login')
def showLogin():
    
    ##Create a 32 characters of pseudo-random alphanumeric variable which 
    #is the anti forgery state token
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
                        
    ##Storing the session the login_session variable
    login_session['state'] = state
    
    ##Rendering the login.html template passing the token as statevariable 
    return render_template('login.html', STATE=state)
    
    
@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token


    app_id = json.loads(open('fb_client_secrets.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]


    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    ''' 
        Due to the formatting for the result from the server token exchange we have to 
        split the token first on commas and select the first index which gives us the key : value 
        for the server access token then we split it on colons to pull out the actual token value
        and replace the remaining quotes with nothing so that it can be used directly in the graph
        api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output
    
    
@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    
    del login_session['username']
    del login_session['email']
    del login_session['picture']
    del login_session['user_id']  
    del login_session['facebook_id']    
    
    return "you have been logged out"


##Creating a routing for GConnect that only accepts post request
@app.route('/gconnect', methods=['POST'])
def gconnect():
    
    ##if statement to make sure the token the client sent to the server matches the token the server sent to the client
    #This round shift verification is making sure the user is making the request and not a malicious script
    #request.args extract the state token passed in from the post request and compares it to the login state session
    if request.args.get('state') != login_session['state']:
        
        ##If the two tokens do not match then create a response of an invalid state token
        #and return the message to the client        
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        
        response.headers['Content-Type'] = 'application/json'
        
        ##return the response to the client and no further authentication will take place in the server side
        return response

        
    ##Collecting the onetime code from the server
    code = request.data


    ##Next we will try to use the one time code and exchange it for credential object 
    #which will contain the access token for the server
    try:
        
        ##Creating an oauth flow object and adding client secret key information stored in the json to it
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        
        ##Specify with post message that this is the one time code flow that the server will be sending off
        oauth_flow.redirect_uri = 'postmessage'
        
        ##Initiate the exchange using the step2_exchange function passing in the one time code that we extracted
        #the step2_exchange function exchanges an authorization code for a credential object
        credentials = oauth_flow.step2_exchange(code)
      
    ##If an error happens in the exchange and a FlowExchangeError is thrown
    except FlowExchangeError:
        
        ##Sending the response as a json object
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
          
        ##Setting the content type of the response object
        response.headers['Content-Type'] = 'application/json'
        
        ##Returning the response to the client
        return response

    ####Check that the access token is valid.
    
    ##Storing the access token in a variable
    access_token = credentials.access_token
    
    ##Appending the token to the following google url so that the google server can verify the validity of the token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s' % access_token)
    
    ##Creating a get request and storing it in a JSON
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    
    ##If the result contained an error then 500 internal server error is sent to the client
    #if the statement is false then we have a working access token
    if result.get('error') is not None:
        
        ##Sending the response as a json object
        response = make_response(json.dumps(result.get('error')), 500)
        
        ##Setting the content type of the response object
        response.headers['Content-Type'] = 'application/json'
        
        ##Returning the response to the client
        return response
    
    ####Verify that the access token is used for the intended user.    
    
    ##Extract the id of the token from the credentials object
    gplus_id = credentials.id_token['sub']
    
    ##Compare the extracted id to the id returned by the google api server 
    if result['user_id'] != gplus_id:
        
        ##if the ids do not match then we do not have the current token
        #so we return an error respone to the client
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        
        ##Setting the content type of the response object
        response.headers['Content-Type'] = 'application/json'
        
        ##Returning the response to the client
        return response

    ####Verifying the client id
    
    ##if the client ids of the token do not match then we return an error respone to the client
    if result['issued_to'] != CLIENT_ID:
        
        ##Making a 401 JSON response
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
            
        ##Printing an arror message
        print "Token's client ID does not match app's."
        
        ##Setting the content type of the response object        
        response.headers['Content-Type'] = 'application/json'
        
        ##Returning the response to the client
        return response

    ####Check if the user is already logged in to the system
    
    ##Extracting the access token from the login session
    stored_credentials = login_session.get('credentials')
    ##Extracting the id from google api server from the login session
    stored_gplus_id = login_session.get('gplus_id')
    
    ##If there is no stored access token from the login session and
    #id extracted from google api server matches to the id extracted previosly from credentials object
    #then make a 200 response that the user is already connected
    if stored_credentials is not None and gplus_id == stored_gplus_id:
        
        ##Making 200 JSON response
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        #Setting the content type of the response object
        response.headers['Content-Type'] = 'application/json'
        
        ##Returning the response to the client
        return response
        
    ####Assuming that none of the preceding if statements are true 

    ##We have valid access token in the session, so we store them  for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    ####Get user info

    ##User info url
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    ##Required parameters for the get request, one of them is the access token
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    ##Extracting the user data from the get request
    answer = requests.get(userinfo_url, params=params)
    ##Serializing the user data into a json object
    data = answer.json()
    
    ##Adding the login session provider
    login_session['provider'] = 'google'

    ##Extracting only the useful information of the user data and storing it in login session
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    
    ####Seeeing if the user exists, if it doesnt then make a new one
    
    ##Extracting the user id from the database by email retrieved from the login session
    user_id = getUserID(data["email"])
    
    ##If there is no user id then make a new user object using data from login session
    if not user_id:
        
        user_id = createUser(login_session)
        
    ##setting the user id of the login session
    login_session['user_id'] = user_id

    ##Creating the output response
    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    
    ##Returning the response
    return output
    

   
def createUser(login_session):
    
    '''a function to create a new user from the login information'''
    
    ##Creating a new user object by extracting information from the login session
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
        
    ##Adding the new user to the database           
    session.add(newUser)
    
    ##Commiting the new user to the database
    session.commit()
    
    ##Extracting the user id from the database
    user = session.query(User).filter_by(email=login_session['email']).one()
    
    ##returning the user id
    return user.id
    
    

def getUserInfo(user_id):

    '''a function to extract the user object by the id'''

    ##Extractign the user by id    
    user = session.query(User).filter_by(id=user_id).one()
    
    ##Returning the user object
    return user
    


def getUserID(email):
    
    
    '''a function to extract the user id by email'''     
    
    try:
        
        ##Extract the user by email
        user = session.query(User).filter_by(email=email).one()
        ##return the user id
        return user.id
        
    except:
        
        return None
    
    

# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] != '200':
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response
         

# JSON APIs to view Restaurant Information
@app.route('/restaurant/<int:restaurant_id>/menu/JSON')
def restaurantMenuJSON(restaurant_id):
    
    ##Querying the restaurant object from the database by restaurant id
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()

    ##Querying all the menu items of the restaurant by restaurant id    
    items = session.query(MenuItem).filter_by(
        restaurant_id=restaurant_id).all()
        
    ##Jsonifying each item and returning the json as response to get request
    return jsonify(MenuItems=[i.serialize for i in items])


@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/JSON')
def menuItemJSON(restaurant_id, menu_id):
    
    ##Querying the menu item by menu id given as the routing paramter
    Menu_Item = session.query(MenuItem).filter_by(id=menu_id).one()
    
    ##Jsonifying the menu item and returning the json as response to get request
    return jsonify(Menu_Item=Menu_Item.serialize)


@app.route('/restaurant/JSON')
def restaurantsJSON():
    
    ##Quering all restaurants from the database
    restaurants = session.query(Restaurant).all()
    
    ##Jsonifying each restaurant items and returing the json as response to get request
    return jsonify(restaurants=[r.serialize for r in restaurants])


# Show all restaurants
@app.route('/')
@app.route('/restaurant/')
def showRestaurants():

    ##Extracting the restaurants in ascending order by name
    restaurants = session.query(Restaurant).order_by(asc(Restaurant.name))
    
    ##if the username field is not in login session
    if 'username' not in login_session:
        
        ##render the public template and passing the retrieved restaurants as template parameters
        return render_template('publicrestaurants.html', restaurants=restaurants)
    else:
        
        ##render the private template and passing the retrieved restaurants as template parameters
        return render_template('restaurants.html', restaurants=restaurants)
        

# Create a new restaurant
@app.route('/restaurant/new/', methods=['GET', 'POST']) ##routing accepts both get and post method
def newRestaurant():
    
    ##if the username is not in login sesssion then redirect to login page
    if 'username' not in login_session:
        return redirect('/login')
        
    ##if the request method is post
    if request.method == 'POST':
        
        ##Create a new restaurant object using the name retrieved from post request 
        #and user id retrieved from the login session
        newRestaurant = Restaurant(
            name=request.form['name'], user_id=login_session['user_id'])
        
        ##Staging the new restaurant 
        session.add(newRestaurant)
        
        ##Setting a flash message 
        flash('New Restaurant %s Successfully Created' % newRestaurant.name)
        
        ##Committing the change to the database
        session.commit()
        
        ##Redirecting to the url for showRestaurants
        return redirect(url_for('showRestaurants'))
    
    ##if there is a get request then render the newRestaurant.html template
    else:
        
        return render_template('newRestaurant.html')


# Edit a restaurant
@app.route('/restaurant/<int:restaurant_id>/edit/', methods=['GET', 'POST']) ##routing accepts both get and post method
def editRestaurant(restaurant_id):
    
    ##Querying the restaurant from the database by restaurant id given as a get parameter
    editedRestaurant = session.query(
        Restaurant).filter_by(id=restaurant_id).one()
        
    ##if the username is not in login session then redirect to the login page
    if 'username' not in login_session:
        return redirect('/login')
        
    ##if the user id of the login session does not match the user id of the restaruant then give a warning alert
    if editedRestaurant.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to edit this restaurant. Please create your own restaurant in order to edit.');}</script><body onload='myFunction()''>"

    ##if the request method id post    
    if request.method == 'POST':
        
        ##if a name parameter is received from the request form
        if request.form['name']:
            
            ##Setting the name of the restaurant to the name retrieved from the post request
            editedRestaurant.name = request.form['name']
            
            ##Setting a flash message 
            flash('Restaurant Successfully Edited %s' % editedRestaurant.name)
            
            ##Redirect to the url for showRestaurants
            return redirect(url_for('showRestaurants'))
    
    ##if there is a get request then render the template of editedRestaurant.html 
    else:
        return render_template('editRestaurant.html', restaurant=editedRestaurant)


# Delete a restaurant
@app.route('/restaurant/<int:restaurant_id>/delete/', methods=['GET', 'POST']) ##routing accepts both get and post requests
def deleteRestaurant(restaurant_id):

    ##Querying the restaurant from the database by restaurant id given as a get parameter    
    restaurantToDelete = session.query(
        Restaurant).filter_by(id=restaurant_id).one()
        
    ##if the username is not in login session then redirect to the login page
    if 'username' not in login_session:
        return redirect('/login')
        
    ##if the user id of the login session does not match the user id of the restaruant then give a warning alert
    if restaurantToDelete.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to delete this restaurant. Please create your own restaurant in order to delete.');}</script><body onload='myFunction()''>"

    ##if the request method is post    
    if request.method == 'POST':
        
        ##Deleting the restaurant        
        session.delete(restaurantToDelete)
        
        ##Setting a flash message 
        flash('%s Successfully Deleted' % restaurantToDelete.name)
        
        ##Committing the change to the database
        session.commit()
        
        ##redirecting the to the url for showRestaurants passing the restaurant id as the template parameter
        return redirect(url_for('showRestaurants', restaurant_id=restaurant_id))

    ##if there is a get request then render the template of deleteRestaurant.html     
    else:
        return render_template('deleteRestaurant.html', restaurant=restaurantToDelete)


# Show a restaurant menu


@app.route('/restaurant/<int:restaurant_id>/')
@app.route('/restaurant/<int:restaurant_id>/menu/')
def showMenu(restaurant_id):
    
    ##Retrieving the restaurant from database by restaurant id retrieved from the get parameters
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    
    ##Retrieving the creator (user) of the restaurant by restaurant's user id
    creator = getUserInfo(restaurant.user_id)
    
    ##Retrieving the menu items of the restaurant
    items = session.query(MenuItem).filter_by(
        restaurant_id=restaurant_id).all()
        
    ##if the username field is not in the login session
    #or the creator id does not match the login session user id
    #then render the public template
    #or else render the private template
    if 'username' not in login_session or creator.id != login_session['user_id']:
        
        ##passing the items, restaurantm and user as the template variables
        return render_template('publicmenu.html', items=items, restaurant=restaurant, creator=creator)
    else:
        
        ##passing the items, restaurantm and user as the template variables
        return render_template('menu.html', items=items, restaurant=restaurant, creator=creator)



# Create a new menu item
@app.route('/restaurant/<int:restaurant_id>/menu/new/', methods=['GET', 'POST']) ##routing accepts both get and post requests
def newMenuItem(restaurant_id):
    
    ##if the username is not in login session then redirect to the login page
    if 'username' not in login_session:
        return redirect('/login')
        
    ##querying the restaurant object from the database by restaurant id
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    
    ##if the user id of the login session does not match the user id of the restaruant then give a warning alert
    if login_session['user_id'] != restaurant.user_id:
        return "<script>function myFunction() {alert('You are not authorized to add menu items to this restaurant. Please create your own restaurant in order to add items.');}</script><body onload='myFunction()''>"
    
    ##if the request method is post
    if request.method == 'POST':
        
        ##Creating a new MenuItem by using fields from the form
        newItem = MenuItem(name=request.form['name'], description=request.form['description'], price=request.form[
                           'price'], course=request.form['course'], restaurant_id=restaurant_id, user_id=restaurant.user_id)
        
        ##Adding the MenuItem 
        session.add(newItem)
        
        ##Committing the change to the database
        session.commit()
        
        ##Setting a flash message
        flash('New Menu %s Item Successfully Created' % (newItem.name))
        
        ##redirect to the url for showMenu, passing the restaurant_id as the routing parameter
        return redirect(url_for('showMenu', restaurant_id=restaurant_id))
    
    ##if there is a get request then render the template of newmenuitem.html    
    else:
        
        return render_template('newmenuitem.html', restaurant_id=restaurant_id)
        


# Edit a menu item
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/edit', methods=['GET', 'POST']) ##routing accepts both get and post requests
def editMenuItem(restaurant_id, menu_id):
    
    ##if the username is not in login session then redirect to the login page
    if 'username' not in login_session:
        return redirect('/login')
        
    ##Querying the menu item from the database by menu id
    editedItem = session.query(MenuItem).filter_by(id=menu_id).one()
    
    ##Querying the restaurant from the database by restaurant id
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    
    ##if the user id of the login session does not match the user id of the restaruant then give a warning alert
    if login_session['user_id'] != restaurant.user_id:
        return "<script>function myFunction() {alert('You are not authorized to edit menu items to this restaurant. Please create your own restaurant in order to edit items.');}</script><body onload='myFunction()''>"
    
    ##If the request method is post    
    if request.method == 'POST':
        
        ##change the menu item name to the name retrieved from the form post request 
        if request.form['name']:
            editedItem.name = request.form['name']
         
        ##change the menu item description to the name retrieved from the form post request 
        if request.form['description']:
            editedItem.description = request.form['description']
            
        ##change the menu item price to the name retrieved from the form post request 
        if request.form['price']:
            editedItem.price = request.form['price']
          
        ##change the menu item course to the name retrieved from the form post request 
        if request.form['course']:
            editedItem.course = request.form['course']
         
        ##Staging the change
        session.add(editedItem)
        
        ##Committing the edit to the database
        session.commit()
        
        ##Setting a flash message
        flash('Menu Item Successfully Edited')
        
        ##Redirect to the url for showMenu, passing the restaurant_id as the routing parameter
        return redirect(url_for('showMenu', restaurant_id=restaurant_id))
        
    ##if there is a get request then render the template of editmenuitem.html  
    else:
        
        return render_template('editmenuitem.html', restaurant_id=restaurant_id, menu_id=menu_id, item=editedItem)


# Delete a menu item
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/delete', methods=['GET', 'POST']) ##routing accepts both get and post requests
def deleteMenuItem(restaurant_id, menu_id):
    
    ##if the username is not in login session then redirect to the login page
    if 'username' not in login_session:
        return redirect('/login')
        
    ##Querying the restaurant from the database by restaurant id
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    
    ##Querying the menuitem from the database by menu id
    itemToDelete = session.query(MenuItem).filter_by(id=menu_id).one()
    
    ##if the user id of the login session does not match the user id of the restaruant then give a warning alert
    if login_session['user_id'] != restaurant.user_id:
        return "<script>function myFunction() {alert('You are not authorized to delete menu items to this restaurant. Please create your own restaurant in order to delete items.');}</script><body onload='myFunction()''>"
    
    ##If the request method is post    
    if request.method == 'POST':
        
        ##Deleting the menu item from the restaurant
        session.delete(itemToDelete)
        
        ##Committing the change to the database
        session.commit()
        
        ##Setting a flash message
        flash('Menu Item Successfully Deleted')
        
        ##redirect to the url for showMenu, passing the restaurant id as the routing parameter
        return redirect(url_for('showMenu', restaurant_id=restaurant_id))
        
    ##if there is a get request then render the template of deleteMenuItem.html  
    else:
        
        return render_template('deleteMenuItem.html', item=itemToDelete)
        
        
##Routing for disconnecting based on provider
@app.route('/disconnect')
def disconnect():
    
    ##If there is no provider parameter in login_session
    if 'provider' in login_session:
        
        ##if the provider of the login session is google
        if login_session['provider'] == 'google':
            
            ##Executing gdisconnect for diconnecting the user
            gdisconnect()
            
            ##Deleting the google id parameter from login session
            del login_session['gplus_id']
         
        ##if the provider of the login session is facebook
        if login_session['provider'] == 'facebook':
            
            ##Executing fbconnect for disconnecting the user
            fbdisconnect()
            
            ##Deleting the facebook id from login session
            del login_session['facebook_id']

        ##Deleting the common login session parameters
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        
        ##Setting a flash message of a successful log out
        flash("You have successfully been logged out.")
        
        ##redirecting to the url for showRestaurants 
        return redirect(url_for('showRestaurants'))
        
    #else flash the message that user is not logged in and redirect to the url for showRestaurants 
    else:
        
        flash("You were not logged in")
        
        return redirect(url_for('showRestaurants'))   


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host = '0.0.0.0', port = 5050)
