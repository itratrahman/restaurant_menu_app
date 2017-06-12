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
      
    ##If there error happens in the exchange then a FlowExchangeError is thrown
    except FlowExchangeError:
        
        ##Sending the response as a json object
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
          
        ##Setting the content type of the response object
        response.headers['Content-Type'] = 'application/json'
        
        ##returining the response to the client
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
        
        ##returining the response to the client
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
        
        ##returining the response to the client
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
        
        ##returining the response to the client
        return response

    ####Check if the user is already logged in to the system
    
    ##Extracting the access token from the login session
    stored_access_token = login_session.get('access_token')
    ##Extracting the id from google api server from the login session
    stored_gplus_id = login_session.get('gplus_id')
    
    ##If there is not stored access token from the login session and
    #id from extract google api server matches to the id extracted previosly from credentials object
    #then make a 200 response that the user is already connected
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        
        ##Making 200 JSON response
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        #Setting the content type of the response object
        response.headers['Content-Type'] = 'application/json'
        
        ##returining the response to the client
        return response
        
    ####Assuming that none of the preceding if statements are true 

    ##We have valid access token in the session, so we store them  for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    ####Get user info

    ##User info url
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    ##Required paramters for the get request, one of them is the access token
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    ##Extracting the user data from the get request
    answer = requests.get(userinfo_url, params=params)
    ##Serializing the user data into a json object
    data = answer.json()

    ##Extracting only the useful information the user data and storing it in login session
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    
    ####Seeeing if the user exists, if it doesnt then make a new one
    
    ##Extracting the user id from the database by email retrieved from the login session
    user_id = getUserID(login_session['email'])
    
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
    
    ##Extracting the access token from the login session
    access_token = login_session['access_token']
    
    ##Print statements
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: ' 
    print login_session['username']
    
    ##If there is not access token then no user to disconnect so we will return an error for this case
    if access_token is None:
        
        ##Print statement
        print 'Access Token is None'
        
        ##Making a 401 response to the client
        response = make_response(json.dumps('Current user not connected.'), 401)

        ##Setting the content type of the response        
        response.headers['Content-Type'] = 'application/json'
        
        ##Sending the response to the client
        return response
        
    ####Executing HTTP get request to revoke the tokens
        
    ##url for the get request
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    ##Carrying the out the get request
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    ##print statements
    print 'result is '
    print result
    
    ##If a response is received  
    if result['status'] == '200':
        
        ##Deleteting the login session data
        del login_session['access_token'] 
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        
        ##Making a json response to notify the user for successful disconnection
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        ##Setting the header of the response
        response.headers['Content-Type'] = 'application/json'
        ##returning the response to the client
        return response
    
    ##if any response code other than 200 is received
    else:
	
         ##Making an error response to the client
        	response = make_response(json.dumps('Failed to revoke token for given user.', 400))
         ##Setting the headers of the response
        	response.headers['Content-Type'] = 'application/json'
         ##Returning a response to the client
        	return response
         

# JSON APIs to view Restaurant Information
@app.route('/restaurant/<int:restaurant_id>/menu/JSON')
def restaurantMenuJSON(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    items = session.query(MenuItem).filter_by(
        restaurant_id=restaurant_id).all()
    return jsonify(MenuItems=[i.serialize for i in items])


@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/JSON')
def menuItemJSON(restaurant_id, menu_id):
    Menu_Item = session.query(MenuItem).filter_by(id=menu_id).one()
    return jsonify(Menu_Item=Menu_Item.serialize)


@app.route('/restaurant/JSON')
def restaurantsJSON():
    restaurants = session.query(Restaurant).all()
    return jsonify(restaurants=[r.serialize for r in restaurants])


# Show all restaurants
@app.route('/')
@app.route('/restaurant/')
def showRestaurants():
    restaurants = session.query(Restaurant).order_by(asc(Restaurant.name))
    return render_template('restaurants.html', restaurants=restaurants)

# Create a new restaurant


@app.route('/restaurant/new/', methods=['GET', 'POST'])
def newRestaurant():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        newRestaurant = Restaurant(
            name=request.form['name'], user_id=login_session['user_id'])
        session.add(newRestaurant)
        flash('New Restaurant %s Successfully Created' % newRestaurant.name)
        session.commit()
        return redirect(url_for('showRestaurants'))
    else:
        return render_template('newRestaurant.html')

# Edit a restaurant


@app.route('/restaurant/<int:restaurant_id>/edit/', methods=['GET', 'POST'])
def editRestaurant(restaurant_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedRestaurant = session.query(
        Restaurant).filter_by(id=restaurant_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editedRestaurant.name = request.form['name']
            flash('Restaurant Successfully Edited %s' % editedRestaurant.name)
            return redirect(url_for('showRestaurants'))
    else:
        return render_template('editRestaurant.html', restaurant=editedRestaurant)


# Delete a restaurant
@app.route('/restaurant/<int:restaurant_id>/delete/', methods=['GET', 'POST'])
def deleteRestaurant(restaurant_id):
    if 'username' not in login_session:
        return redirect('/login')
    restaurantToDelete = session.query(
        Restaurant).filter_by(id=restaurant_id).one()
    if request.method == 'POST':
        session.delete(restaurantToDelete)
        flash('%s Successfully Deleted' % restaurantToDelete.name)
        session.commit()
        return redirect(url_for('showRestaurants', restaurant_id=restaurant_id))
    else:
        return render_template('deleteRestaurant.html', restaurant=restaurantToDelete)

# Show a restaurant menu


@app.route('/restaurant/<int:restaurant_id>/')
@app.route('/restaurant/<int:restaurant_id>/menu/')
def showMenu(restaurant_id):
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    items = session.query(MenuItem).filter_by(
        restaurant_id=restaurant_id).all()
    return render_template('menu.html', items=items, restaurant=restaurant)


# Create a new menu item
@app.route('/restaurant/<int:restaurant_id>/menu/new/', methods=['GET', 'POST'])
def newMenuItem(restaurant_id):
    if 'username' not in login_session:
        return redirect('/login')
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    if request.method == 'POST':
        newItem = MenuItem(name=request.form['name'], description=request.form['description'], price=request.form[
                           'price'], course=request.form['course'], restaurant_id=restaurant_id, user_id=restaurant.user_id)
        session.add(newItem)
        session.commit()
        flash('New Menu %s Item Successfully Created' % (newItem.name))
        return redirect(url_for('showMenu', restaurant_id=restaurant_id))
    else:
        return render_template('newmenuitem.html', restaurant_id=restaurant_id)

# Edit a menu item


@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/edit', methods=['GET', 'POST'])
def editMenuItem(restaurant_id, menu_id):
    if 'username' not in login_session:
        return redirect('/login')
    editedItem = session.query(MenuItem).filter_by(id=menu_id).one()
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['price']:
            editedItem.price = request.form['price']
        if request.form['course']:
            editedItem.course = request.form['course']
        session.add(editedItem)
        session.commit()
        flash('Menu Item Successfully Edited')
        return redirect(url_for('showMenu', restaurant_id=restaurant_id))
    else:
        return render_template('editmenuitem.html', restaurant_id=restaurant_id, menu_id=menu_id, item=editedItem)


# Delete a menu item
@app.route('/restaurant/<int:restaurant_id>/menu/<int:menu_id>/delete', methods=['GET', 'POST'])
def deleteMenuItem(restaurant_id, menu_id):
    if 'username' not in login_session:
        return redirect('/login')
    restaurant = session.query(Restaurant).filter_by(id=restaurant_id).one()
    itemToDelete = session.query(MenuItem).filter_by(id=menu_id).one()
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Menu Item Successfully Deleted')
        return redirect(url_for('showMenu', restaurant_id=restaurant_id))
    else:
        return render_template('deleteMenuItem.html', item=itemToDelete)
        


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host = '0.0.0.0', port = 5050)
