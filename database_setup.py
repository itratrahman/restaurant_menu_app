##Import statements
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine


##Creating a declarative base class
Base = declarative_base()


####Creating a table for user base
class User(Base):
    
    __tablename__ = 'user'

    ##Table columns
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))


####Creating a table for Restaurant
class Restaurant(Base):
    
    __tablename__ = 'restaurant'

    ##Table columns
    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    ##A decorator function to serialize the class object into JSON
    @property
    def serialize(self):
        
        """Return object data in easily serializeable format"""
        return {
            'name': self.name,
            'id': self.id,
            'user_id': self.user_id
        }
        
        
####Creating a table for menuitems
class MenuItem(Base):
    
    __tablename__ = 'menu_item'
    
    ##Table contents
    name = Column(String(80), nullable=False)
    id = Column(Integer, primary_key=True)
    description = Column(String(250))
    price = Column(String(8))
    course = Column(String(250))
    restaurant_id = Column(Integer, ForeignKey('restaurant.id'))
    restaurant = relationship(Restaurant)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)
    
    
    ##A decorator function to serialize the class object into JSON
    @property
    def serialize(self):
        
        """Return object data in easily serializeable format"""
        return {
            'name': self.name,
            'description': self.description,
            'id': self.id,
            'price': self.price,
            'course': self.course,
        }


####Creating a database engine
engine = create_engine('sqlite:///restaurantmenuwithusers.db')
Base.metadata.create_all(engine)