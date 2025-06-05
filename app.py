from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_pymongo import PyMongo
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta, timezone
from functools import wraps
from bson.objectid import ObjectId
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key'  # Change this to a secure secret key
app.config['MONGO_URI'] = 'mongodb+srv://rakshit:agewell@cluster0.svixdcm.mongodb.net/agewell?retryWrites=true&w=majority'

mongo = PyMongo(app)

# Verify MongoDB connection and collections
try:
    # Test database connection
    mongo.db.command('ping')
    print("Successfully connected to MongoDB!")
    
    # Ensure events collection exists
    if 'events' not in mongo.db.list_collection_names():
        mongo.db.create_collection('events')
        print("Created events collection")
    
    # Create indexes for better performance
    mongo.db.events.create_index([('datetime', 1)])
    mongo.db.events.create_index([('organizer_id', 1)])
    print("Created necessary indexes")
except Exception as e:
    print(f"Error connecting to MongoDB: {str(e)}")
    print(f"Error type: {type(e)}")
    import traceback
    print(f"Traceback: {traceback.format_exc()}")

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def get_emergency_contact(user):
    """Helper function to get emergency contact information"""
    emergency_contact = {
        'name': None,
        'phone': None,
        'type': None
    }
    
    # First try to get linked child's contact
    if user['role'] == 'elder':
        linked_child = mongo.db.users.find_one({
            'elder_id': str(user['_id']),
            'role': 'child'
        })
        
        if linked_child and linked_child.get('phone'):
            emergency_contact = {
                'name': linked_child['name'],
                'phone': linked_child['phone'],
                'type': 'child'
            }
            print(f"Using linked child's contact: {linked_child['name']} - {linked_child['phone']}")
        # If no linked child or no phone, use emergency contact
        elif user.get('emergency_contact'):
            emergency_contact = {
                'name': 'Emergency Contact',
                'phone': user['emergency_contact'],
                'type': 'emergency'
            }
            print(f"Using emergency contact: {user['emergency_contact']}")
    
    return emergency_contact

@app.route('/')
def index():
    if 'user_id' in session:
        try:
            user = mongo.db.users.find_one({'_id': ObjectId(session['user_id'])})
            if user:
                if user['role'] == 'child':
                    return redirect(url_for('child_dashboard'))
                else:
                    emergency_contact = get_emergency_contact(user)
                    return render_template('dashboard.html', 
                                         user=user,
                                         emergency_contact=emergency_contact)
        except Exception as e:
            print(f"Error in index route: {str(e)}")
            flash('Error loading dashboard', 'error')
    return render_template('index.html')

@app.route('/dashboard')
@login_required
def dashboard():
    try:
        user = mongo.db.users.find_one({'_id': ObjectId(session['user_id'])})
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('index'))
            
        if user['role'] == 'child':
            return redirect(url_for('child_dashboard'))
            
        emergency_contact = get_emergency_contact(user)
        
        # Get today's medicines
        today = datetime.now()
        today_start = datetime.combine(today.date(), datetime.min.time())
        today_end = datetime.combine(today.date(), datetime.max.time())
        
        today_medicines = list(mongo.db.medicine_schedule.find({
            'user_id': ObjectId(session['user_id']),
            'date': {
                '$gte': today_start,
                '$lte': today_end
            },
            'is_taken': False
        }).sort('time', 1))
        
        # Get upcoming reminders (next 3 days)
        three_days_later = today + timedelta(days=3)
        upcoming_reminders = list(mongo.db.reminders.find({
            'user_id': ObjectId(session['user_id']),
            'completed': False,
            'date': {
                '$gte': today.strftime('%Y-%m-%d'),
                '$lte': three_days_later.strftime('%Y-%m-%d')
            }
        }).sort([('date', 1), ('time', 1)]))
        
        # Get upcoming bills (next 7 days)
        seven_days_later = today + timedelta(days=7)
        upcoming_bills = list(mongo.db.fixed_expenses.find({
            'user_id': ObjectId(session['user_id']),
            'is_paid': False,
            'date': {
                '$gte': today,
                '$lte': seven_days_later
            }
        }).sort('date', 1))
        
        return render_template('dashboard.html', 
                             user=user,
                             emergency_contact=emergency_contact,
                             today_medicines=today_medicines,
                             upcoming_reminders=upcoming_reminders,
                             upcoming_bills=upcoming_bills)
    except Exception as e:
        print(f"Error in dashboard route: {str(e)}")
        flash('Error loading dashboard', 'error')
        return redirect(url_for('index'))

@app.route('/child-dashboard')
@login_required
def child_dashboard():
    try:
        user = mongo.db.users.find_one({'_id': ObjectId(session['user_id'])})
        if not user or user['role'] != 'child':
            flash('Access denied', 'error')
            return redirect(url_for('index'))
            
        # Get linked elder's information
        linked_elder = None
        if user.get('elder_id'):
            linked_elder = mongo.db.users.find_one({'_id': ObjectId(user['elder_id'])})
            
            if linked_elder:
                # Get elder's upcoming events
                elder_events = list(mongo.db.events.find({
                    'participants': ObjectId(user['elder_id'])
                }).sort('datetime', 1))
                
                # Get elder's today's medicines
                today = datetime.now()
                today_start = datetime.combine(today.date(), datetime.min.time())
                today_end = datetime.combine(today.date(), datetime.max.time())
                
                today_medicines = list(mongo.db.medicine_schedule.find({
                    'user_id': ObjectId(user['elder_id']),
                    'date': {
                        '$gte': today_start,
                        '$lte': today_end
                    }
                }).sort('time', 1))
                
                # Get elder's recent reminders
                elder_reminders = list(mongo.db.reminders.find({
                    'user_id': ObjectId(user['elder_id']),
                    'completed': False
                }).sort('date', 1).limit(5))
                
                # Get elder's finance summary
                finance_summary = {
                    'total_monthly_expenses': 0,
                    'total_paid_expenses': 0,
                    'pending_fixed_total': 0
                }
                
                # Calculate regular expenses
                regular_expenses = list(mongo.db.regular_expenses.find({
                    'user_id': ObjectId(user['elder_id']),
                    'date': {
                        '$gte': today_start,
                        '$lte': today_end
                    }
                }))
                
                finance_summary['total_monthly_expenses'] = sum(expense['amount'] for expense in regular_expenses)
                
                # Calculate fixed expenses
                fixed_expenses = list(mongo.db.fixed_expenses.find({
                    'user_id': ObjectId(user['elder_id'])
                }))
                
                paid_fixed = sum(expense['amount'] for expense in fixed_expenses if expense.get('is_paid', False))
                total_fixed = sum(expense['amount'] for expense in fixed_expenses)
                
                finance_summary['total_paid_expenses'] = finance_summary['total_monthly_expenses'] + paid_fixed
                finance_summary['pending_fixed_total'] = total_fixed - paid_fixed
                
                # Get emergency logs from the last hour for the linked elder
                one_hour_ago = datetime.utcnow() - timedelta(hours=1)
                emergency_logs = list(mongo.db.emergency_logs.find({
                    'user_id': ObjectId(user['elder_id']),
                    'created_at': {'$gte': one_hour_ago}
                }).sort('created_at', -1))
                
                # Clean up old emergency logs
                cleanup_old_emergency_logs()
                
                return render_template('child_dashboard.html',
                                     user=user,
                                     linked_elder=linked_elder,
                                     elder_events=elder_events,
                                     today_medicines=today_medicines,
                                     elder_reminders=elder_reminders,
                                     finance_summary=finance_summary,
                                     emergency_logs=emergency_logs)
        
        return render_template('child_dashboard.html',
                             user=user,
                             linked_elder=None)
                             
    except Exception as e:
        print(f"Error in child_dashboard route: {str(e)}")
        flash('Error loading dashboard', 'error')
        return redirect(url_for('index'))

def cleanup_old_emergency_logs():
    """Clean up emergency logs older than one hour"""
    try:
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        result = mongo.db.emergency_logs.delete_many({
            'created_at': {'$lt': one_hour_ago}
        })
        if result.deleted_count > 0:
            print(f"Cleaned up {result.deleted_count} old emergency logs")
    except Exception as e:
        print(f"Error cleaning up emergency logs: {str(e)}")

@app.route('/social_events')
@login_required
def social_events():
    try:
        print("\n=== Social Events Debug ===")
        user_id = ObjectId(session['user_id'])
        print(f"Fetching events for user_id: {user_id}")
        
        # Verify MongoDB connection
        try:
            mongo.db.command('ping')
            print("MongoDB connection is active")
        except Exception as e:
            print(f"MongoDB connection error: {str(e)}")
            flash('Database connection error. Please try again.', 'error')
            return redirect(url_for('dashboard'))
        
        # Get all events, sorted by datetime
        events = list(mongo.db.events.find().sort('datetime', 1))
        print(f"Total events found: {len(events)}")
        
        # Get events organized by the current user
        my_events = list(mongo.db.events.find({
            'organizer_id': user_id
        }).sort('datetime', 1))
        print(f"User's events found: {len(my_events)}")
        
        # Get events the user is participating in
        user_participating_events = []
        for event in events:
            if user_id in event.get('participants', []):
                user_participating_events.append(str(event['_id']))
        print(f"User participating in: {len(user_participating_events)} events")
        
        # Get any pending notifications for this page
        notifications = session.pop('social_events_notifications', [])
        
        return render_template('social_events.html', 
                             events=events,
                             my_events=my_events,
                             user_participating_events=user_participating_events,
                             notifications=notifications)
    except Exception as e:
        print(f"\nError in social_events route: {str(e)}")
        print(f"Error type: {type(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        flash('Error loading events. Please try again.', 'error')
        return redirect(url_for('dashboard'))

@app.route('/create_event', methods=['POST'])
@login_required
def create_event():
    try:
        print("\n=== Event Creation Debug ===")
        print("Form data received:", dict(request.form))
        
        # Validate required fields
        required_fields = ['eventName', 'eventDescription', 'eventDate', 'eventTime', 'location']
        for field in required_fields:
            if not request.form.get(field):
                print(f"Missing required field: {field}")
                session['social_events_notifications'] = [{'type': 'error', 'message': f'Missing required field: {field}'}]
                return redirect(url_for('social_events'))

        # Parse date and time
        try:
            event_date = datetime.strptime(request.form.get('eventDate'), '%Y-%m-%d')
            event_time = datetime.strptime(request.form.get('eventTime'), '%H:%M').time()
            event_datetime = datetime.combine(event_date.date(), event_time)
            print(f"Parsed datetime: {event_datetime}")
        except ValueError as e:
            print(f"Date/Time parsing error: {str(e)}")
            session['social_events_notifications'] = [{'type': 'error', 'message': 'Invalid date or time format'}]
            return redirect(url_for('social_events'))
        
        # Validate event date (between 2 and 7 days from now)
        today = datetime.now().date()
        min_date = today + timedelta(days=2)
        max_date = today + timedelta(days=7)
        
        if not (min_date <= event_date.date() <= max_date):
            print(f"Invalid date: {event_date.date()}. Must be between {min_date} and {max_date}")
            session['social_events_notifications'] = [{'type': 'error', 'message': 'Event date must be between 2 and 7 days from now.'}]
            return redirect(url_for('social_events'))

        # Validate event time (between 5:00 AM and 10:00 PM)
        if not (5 <= event_time.hour < 22 or (event_time.hour == 22 and event_time.minute == 0)):
            print(f"Invalid time: {event_time}")
            session['social_events_notifications'] = [{'type': 'error', 'message': 'Event time must be between 5:00 AM and 10:00 PM.'}]
            return redirect(url_for('social_events'))

        # Get organizer details
        user_id = ObjectId(session['user_id'])
        organizer = mongo.db.users.find_one({'_id': user_id})
        if not organizer:
            print(f"Organizer not found for user_id: {session['user_id']}")
            session['social_events_notifications'] = [{'type': 'error', 'message': 'User not found!'}]
            return redirect(url_for('social_events'))

        # Create event document
        event = {
            'name': request.form.get('eventName'),
            'description': request.form.get('eventDescription'),
            'datetime': event_datetime,
            'location': request.form.get('location'),
            'max_participants': int(request.form.get('maxParticipants', 1)),
            'organizer_id': user_id,
            'organizer_name': organizer['name'],
            'participants': [user_id],
            'created_at': datetime.now(timezone.utc)
        }

        # Insert event
        try:
            result = mongo.db.events.insert_one(event)
            print(f"\nInsert result: {result.inserted_id}")
            
            if result.inserted_id:
                # Verify the event was inserted
                inserted_event = mongo.db.events.find_one({'_id': result.inserted_id})
                if inserted_event:
                    print("Event successfully verified in database")
                    session['social_events_notifications'] = [{'type': 'success', 'message': 'Event created successfully!'}]
                else:
                    print("Event not found after insertion!")
                    session['social_events_notifications'] = [{'type': 'error', 'message': 'Error verifying event creation. Please try again.'}]
            else:
                print("Failed to create event - no inserted_id returned")
                session['social_events_notifications'] = [{'type': 'error', 'message': 'Error creating event. Please try again.'}]
                
        except Exception as e:
            print(f"\nDatabase insertion error: {str(e)}")
            print(f"Error type: {type(e)}")
            import traceback
            print(f"Traceback: {traceback.format_exc()}")
            session['social_events_notifications'] = [{'type': 'error', 'message': 'Error creating event. Please try again.'}]
            
    except Exception as e:
        print(f"\nGeneral error: {str(e)}")
        print(f"Error type: {type(e)}")
        import traceback
        print(f"Traceback: {traceback.format_exc()}")
        session['social_events_notifications'] = [{'type': 'error', 'message': 'Error creating event. Please try again.'}]
    
    print("\n=== End Event Creation Debug ===\n")
    return redirect(url_for('social_events'))

@app.route('/event/<event_id>')
@login_required
def view_event(event_id):
    try:
        event = mongo.db.events.find_one({'_id': ObjectId(event_id)})
        if not event:
            flash('Event not found!', 'error')
            return redirect(url_for('social_events'))
        
        # Get participants' details with join times
        participants = []
        for participant_id in event['participants']:
            user = mongo.db.users.find_one({'_id': participant_id})
            if user:
                # Get the join time from the event's participants array
                join_time = event.get('participant_join_times', {}).get(str(participant_id), event['created_at'])
                participants.append({
                    'name': user['name'],
                    'email': user['email'],
                    'join_time': join_time
                })
        
        # Sort participants by join time
        participants.sort(key=lambda x: x['join_time'], reverse=True)
        
        # Check if current user is participating
        is_participating = ObjectId(session['user_id']) in event['participants']
        
        return render_template('view_event.html', 
                             event=event, 
                             participants=participants,
                             is_participating=is_participating)
    except Exception as e:
        print(f"Error viewing event: {str(e)}")
        flash('Error viewing event!', 'error')
        return redirect(url_for('social_events'))

@app.route('/event/join/<event_id>', methods=['POST'])
@login_required
def join_event(event_id):
    try:
        user_id = ObjectId(session['user_id'])
        event = mongo.db.events.find_one({'_id': ObjectId(event_id)})
        if not event:
            return jsonify({'success': False, 'message': 'Event not found'})

        if len(event['participants']) >= event['max_participants']:
            return jsonify({'success': False, 'message': 'Event is full'})

        if user_id in event['participants']:
            return jsonify({'success': False, 'message': 'You are already participating in this event'})

        # Add participant with join time
        current_time = datetime.now(timezone.utc)
        mongo.db.events.update_one(
            {'_id': ObjectId(event_id)},
            {
                '$push': {'participants': user_id},
                '$set': {f'participant_join_times.{str(user_id)}': current_time}
            }
        )
        session['social_events_notifications'] = [{'type': 'success', 'message': 'Successfully joined the event!'}]
        return jsonify({'success': True})
    except Exception as e:
        print(f"Error joining event: {str(e)}")
        return jsonify({'success': False, 'message': 'Error joining event'})

@app.route('/event/leave/<event_id>', methods=['POST'])
@login_required
def leave_event(event_id):
    try:
        user_id = ObjectId(session['user_id'])
        event = mongo.db.events.find_one({'_id': ObjectId(event_id)})
        
        if not event:
            return jsonify({'success': False, 'message': 'Event not found'})
            
        # Check if user is the organizer
        if event['organizer_id'] == user_id:
            return jsonify({'success': False, 'message': 'Event organizers cannot leave their own events. Please delete the event instead.'})
            
        mongo.db.events.update_one(
            {'_id': ObjectId(event_id)},
            {
                '$pull': {'participants': user_id},
                '$unset': {f'participant_join_times.{str(user_id)}': ""}
            }
        )
        session['social_events_notifications'] = [{'type': 'success', 'message': 'Successfully left the event'}]
        return jsonify({'success': True})
    except Exception as e:
        print(f"Error leaving event: {str(e)}")
        return jsonify({'success': False, 'message': 'Error leaving event'})

@app.route('/event/delete/<event_id>', methods=['POST'])
@login_required
def delete_event(event_id):
    try:
        user_id = ObjectId(session['user_id'])
        event = mongo.db.events.find_one({'_id': ObjectId(event_id)})
        
        if not event:
            return jsonify({'success': False, 'message': 'Event not found'})
            
        # Check if user is the organizer
        if event['organizer_id'] != user_id:
            return jsonify({'success': False, 'message': 'Only event organizers can delete events'})
            
        # Delete the event
        result = mongo.db.events.delete_one({'_id': ObjectId(event_id)})
        
        if result.deleted_count > 0:
            session['social_events_notifications'] = [{'type': 'success', 'message': 'Event deleted successfully'}]
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': 'Error deleting event'})
            
    except Exception as e:
        print(f"Error deleting event: {str(e)}")
        return jsonify({'success': False, 'message': 'Error deleting event'})

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get form data
        name = request.form.get('name')
        email = request.form.get('email')
        phone = request.form.get('phone')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        role = request.form.get('role')
        gender = request.form.get('gender')
        age = request.form.get('age')
        parent_email = request.form.get('parent_email')
        
        # Address information
        address = request.form.get('address')
        city = request.form.get('city')
        state = request.form.get('state')
        pincode = request.form.get('pincode')
        emergency_contact = request.form.get('emergency_contact')

        # Validate required fields
        if not all([name, email, phone, password, confirm_password, role, gender, age, address, city, state, pincode]):
            flash('Please fill in all required fields', 'error')
            return redirect(url_for('register'))

        # Validate email format
        if not '@' in email or not '.' in email:
            flash('Please enter a valid email address', 'error')
            return redirect(url_for('register'))

        # Validate phone number
        if not phone.isdigit() or len(phone) != 10:
            flash('Please enter a valid 10-digit phone number', 'error')
            return redirect(url_for('register'))

        # Validate PIN code
        if not pincode.isdigit() or len(pincode) != 6:
            flash('Please enter a valid 6-digit PIN code', 'error')
            return redirect(url_for('register'))

        # Validate age
        try:
            age = int(age)
            if age < 0 or age > 120:
                flash('Please enter a valid age (0-120)', 'error')
                return redirect(url_for('register'))
        except ValueError:
            flash('Please enter a valid age', 'error')
            return redirect(url_for('register'))

        # Validate password
        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('register'))
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long', 'error')
            return redirect(url_for('register'))

        # Check if email already exists
        if mongo.db.users.find_one({'email': email}):
            flash('Email already registered!', 'error')
            return redirect(url_for('register'))

        # If registering as a child, verify parent's email
        elder_id = None
        if role == 'child':
            if not parent_email:
                flash('Parent email is required for family members', 'error')
                return redirect(url_for('register'))
                
            elder = mongo.db.users.find_one({'email': parent_email, 'role': 'elder'})
            if not elder:
                flash('Parent email not found or is not registered as a senior citizen!', 'error')
                return redirect(url_for('register'))
            elder_id = str(elder['_id'])

        # Create new user
        user = {
            'name': name,
            'email': email,
            'phone': phone,
            'password_hash': generate_password_hash(password),
            'role': role,
            'gender': gender,
            'age': age,
            'elder_id': elder_id,
            'address': {
                'street': address,
                'city': city,
                'state': state,
                'pincode': pincode
            },
            'emergency_contact': emergency_contact,
            'created_at': datetime.utcnow()
        }

        try:
            result = mongo.db.users.insert_one(user)
            flash('Registration successful! Please login.', 'success')
            return redirect(url_for('login'))
        except Exception as e:
            print(f"Error during registration: {str(e)}")
            flash('Error during registration. Please try again.', 'error')
            return redirect(url_for('register'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Check for admin login
        if email == 'admin@agewell.in' and password == 'admin@1':
            session['user_id'] = 'admin'
            session['is_admin'] = True
            session['role'] = 'admin'
            flash('Welcome Admin!', 'success')
            return redirect(url_for('admin_dashboard'))

        # Regular user login
        user = mongo.db.users.find_one({'email': email})
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = str(user['_id'])
            session['is_admin'] = False
            session['role'] = user['role']
            flash('Login successful!', 'success')
            return redirect(url_for('index'))
        
        flash('Invalid email or password!', 'error')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    try:
        user = mongo.db.users.find_one({'_id': ObjectId(session['user_id'])})
        if not user:
            flash('User not found!', 'error')
            return redirect(url_for('dashboard'))
            
        linked_elder = None
        linked_children = None
        
        if user['role'] == 'child' and user.get('elder_id'):
            linked_elder = mongo.db.users.find_one({'_id': ObjectId(user['elder_id'])})
        elif user['role'] == 'elder':
            linked_children = list(mongo.db.users.find({'elder_id': str(user['_id'])}))
            
        # Get any pending notifications for this page
        notifications = session.pop('profile_notifications', [])
        
        return render_template('profile.html', 
                             user=user, 
                             linked_elder=linked_elder,
                             linked_children=linked_children,
                             notifications=notifications)
    except Exception as e:
        print(f"Error in profile route: {str(e)}")
        flash('Error loading profile!', 'error')
        return redirect(url_for('dashboard'))

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    try:
        user_id = ObjectId(session['user_id'])
        user = mongo.db.users.find_one({'_id': user_id})
        
        if not user:
            session['profile_notifications'] = [{'type': 'error', 'message': 'User not found!'}]
            return redirect(url_for('profile'))
        
        # Get form data
        name = request.form.get('name')
        phone = request.form.get('phone')
        age = request.form.get('age')
        gender = request.form.get('gender')
        
        # Validate required fields
        if not name or not phone:
            session['profile_notifications'] = [{'type': 'error', 'message': 'Name and phone number are required!'}]
            return redirect(url_for('profile'))
            
        # Validate phone number (basic validation)
        if not phone.isdigit() or len(phone) < 10:
            session['profile_notifications'] = [{'type': 'error', 'message': 'Please enter a valid phone number!'}]
            return redirect(url_for('profile'))
            
        # Validate age if provided
        if age:
            try:
                age = int(age)
                if age < 0 or age > 120:
                    session['profile_notifications'] = [{'type': 'error', 'message': 'Please enter a valid age!'}]
                    return redirect(url_for('profile'))
            except ValueError:
                session['profile_notifications'] = [{'type': 'error', 'message': 'Please enter a valid age!'}]
                return redirect(url_for('profile'))
        
        # Prepare update data
        update_data = {
            'name': name,
            'phone': phone,
            'gender': gender
        }
        
        if age:
            update_data['age'] = age
            
        # Handle password change if provided
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        if current_password and new_password and confirm_password:
            # Verify current password
            if not check_password_hash(user['password_hash'], current_password):
                session['profile_notifications'] = [{'type': 'error', 'message': 'Current password is incorrect!'}]
                return redirect(url_for('profile'))
                
            # Validate new password
            if new_password != confirm_password:
                session['profile_notifications'] = [{'type': 'error', 'message': 'New passwords do not match!'}]
                return redirect(url_for('profile'))
                
            if len(new_password) < 6:
                session['profile_notifications'] = [{'type': 'error', 'message': 'Password must be at least 6 characters long!'}]
                return redirect(url_for('profile'))
                
            # Update password
            update_data['password_hash'] = generate_password_hash(new_password)
        
        # Update user profile
        try:
            result = mongo.db.users.update_one(
                {'_id': user_id},
                {'$set': update_data}
            )
            
            if result.modified_count > 0:
                session['profile_notifications'] = [{'type': 'success', 'message': 'Profile updated successfully!'}]
            else:
                session['profile_notifications'] = [{'type': 'info', 'message': 'No changes were made to your profile.'}]
                
        except Exception as e:
            print(f"Error updating profile: {str(e)}")
            session['profile_notifications'] = [{'type': 'error', 'message': 'Error updating profile. Please try again.'}]
            
    except Exception as e:
        print(f"Error in update_profile route: {str(e)}")
        session['profile_notifications'] = [{'type': 'error', 'message': 'Error updating profile. Please try again.'}]
        
    return redirect(url_for('profile'))

@app.route('/admin-dashboard')
@login_required
def admin_dashboard():
    try:
        # Check if user is admin
        if not session.get('is_admin'):
            flash('Access denied', 'error')
            return redirect(url_for('index'))
            
        # Get all users
        users = list(mongo.db.users.find())
        
        # Get all events
        events = list(mongo.db.events.find().sort('datetime', 1))
        
        # Get all medicine schedules
        medicine_schedules = list(mongo.db.medicine_schedule.find().sort('date', 1))
        
        # Get all reminders
        reminders = list(mongo.db.reminders.find().sort('date', 1))
        
        # Get all regular expenses
        regular_expenses = list(mongo.db.regular_expenses.find().sort('date', 1))
        
        # Get all fixed expenses
        fixed_expenses = list(mongo.db.fixed_expenses.find())
        
        # Get all feedback items
        feedback_items = list(mongo.db.feedback.find().sort('created_at', -1))
        
        # Get all tutorial requests
        tutorial_requests = list(mongo.db.tutorial_requests.find().sort('created_at', -1))
        
        # Get emergency logs from the last hour
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        emergency_logs = list(mongo.db.emergency_logs.find({
            'created_at': {'$gte': one_hour_ago}
        }).sort('created_at', -1))
        
        # Clean up old emergency logs
        cleanup_old_emergency_logs()
        
        return render_template('admin_dashboard.html',
                             users=users,
                             events=events,
                             medicine_schedules=medicine_schedules,
                             reminders=reminders,
                             regular_expenses=regular_expenses,
                             fixed_expenses=fixed_expenses,
                             feedback_items=feedback_items,
                             tutorial_requests=tutorial_requests,
                             emergency_logs=emergency_logs)
                             
    except Exception as e:
        print(f"Error in admin_dashboard route: {str(e)}")
        flash('Error loading dashboard', 'error')
        return redirect(url_for('index'))

@app.route('/admin/user/<user_id>')
@login_required
def admin_user_details(user_id):
    if not session.get('is_admin'):
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('admin_dashboard'))
    
    try:
        # Get user details
        user = mongo.db.users.find_one({'_id': ObjectId(user_id)})
        if not user:
            flash('User not found', 'error')
            return redirect(url_for('admin_dashboard'))
        
        # Get linked children if user is an elder
        linked_children = []
        if user['role'] == 'elder':
            linked_children = list(mongo.db.users.find({'elder_id': str(user['_id'])}))
        
        # Get linked elder if user is a child
        linked_elder = None
        if user['role'] == 'child' and user.get('elder_id'):
            linked_elder = mongo.db.users.find_one({'_id': ObjectId(user['elder_id'])})
        
        return render_template('admin_user_details.html', 
                             user=user,
                             linked_children=linked_children,
                             linked_elder=linked_elder)
    except Exception as e:
        print(f"Error in admin_user_details: {str(e)}")
        flash('Error loading user details', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/feedback/update/<feedback_id>', methods=['POST'])
def admin_update_feedback(feedback_id):
    if not session.get('is_admin'):
        return jsonify({'success': False, 'message': 'Access denied'})
    
    try:
        status = request.form.get('status')
        if status not in ['pending', 'resolved']:
            return jsonify({'success': False, 'message': 'Invalid status'})
        
        result = mongo.db.feedback.update_one(
            {'_id': ObjectId(feedback_id)},
            {'$set': {'status': status}}
        )
        
        if result.modified_count > 0:
            return jsonify({'success': True})
        return jsonify({'success': False, 'message': 'Failed to update status'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/feedback/delete/<feedback_id>', methods=['POST'])
def admin_delete_feedback(feedback_id):
    if not session.get('is_admin'):
        return jsonify({'success': False, 'message': 'Access denied'})
    
    try:
        result = mongo.db.feedback.delete_one({'_id': ObjectId(feedback_id)})
        if result.deleted_count > 0:
            return jsonify({'success': True})
        return jsonify({'success': False, 'message': 'Failed to delete feedback'})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

# Add a route for users to submit feedback/complaints/requests
@app.route('/submit_feedback', methods=['POST'])
@login_required
def submit_feedback():
    try:
        # Get form data
        feedback_type = request.form.get('type')
        rating = request.form.get('rating')
        message = request.form.get('message')
        priority = request.form.get('priority')
        
        # Handle file upload
        file_path = None
        if 'file' in request.files:
            file = request.files['file']
            if file and file.filename:
                # Create uploads directory if it doesn't exist
                upload_dir = os.path.join(app.static_folder, 'uploads', 'feedback')
                os.makedirs(upload_dir, exist_ok=True)
                
                # Generate unique filename
                filename = secure_filename(file.filename)
                unique_filename = f"{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{filename}"
                file_path = os.path.join('uploads', 'feedback', unique_filename)
                
                # Save file
                file.save(os.path.join(app.static_folder, file_path))
        
        # Create feedback entry
        feedback = {
            'user_id': ObjectId(session['user_id']),
            'type': feedback_type,
            'rating': int(rating) if rating else None,  # Convert rating to integer
            'message': message,
            'priority': priority,
            'file_path': file_path,
            'status': 'pending',
            'created_at': datetime.utcnow()
        }
        
        # Debug print
        print(f"Debug - Submitting feedback: {feedback}")
        
        result = mongo.db.feedback.insert_one(feedback)
        if result.inserted_id:
            return jsonify({
                'success': True,
                'message': 'Feedback submitted successfully'
            })
        return jsonify({
            'success': False,
            'message': 'Failed to submit feedback'
        }), 500
    except Exception as e:
        print(f"Error submitting feedback: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Error submitting feedback'
        }), 500

@app.route('/admin/feedback')
@login_required
def admin_feedback():
    if not session.get('is_admin'):
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('dashboard'))
    
    try:
        # Get all feedback with user details
        feedback_list = list(mongo.db.feedback.find().sort('created_at', -1))
        
        # Add user details to each feedback
        for feedback in feedback_list:
            user = mongo.db.users.find_one({'_id': feedback['user_id']})
            feedback['user_name'] = user['name'] if user else 'Unknown User'
            
            # Ensure rating is included
            if 'rating' not in feedback:
                feedback['rating'] = None
            else:
                feedback['rating'] = int(feedback['rating'])
            
            # Convert ObjectId to string for JSON serialization
            feedback['_id'] = str(feedback['_id'])
            feedback['user_id'] = str(feedback['user_id'])
            
            # Format datetime
            if isinstance(feedback.get('created_at'), datetime):
                feedback['created_at'] = feedback['created_at'].strftime('%Y-%m-%d %H:%M')
        
        print(f"Debug - First feedback item: {feedback_list[0] if feedback_list else 'No feedback found'}")
        
        return render_template('admin/feedback.html', feedback_list=feedback_list)
    except Exception as e:
        print(f"Error in admin_feedback: {str(e)}")
        flash('Error loading feedback', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/feedback/<feedback_id>/update', methods=['POST'])
@login_required
def update_feedback_status(feedback_id):
    if not session.get('is_admin'):
        return jsonify({'success': False, 'message': 'Access denied'}), 403
    
    try:
        feedback = mongo.db.feedback.find_one({'_id': ObjectId(feedback_id)})
        if not feedback:
            return jsonify({'success': False, 'message': 'Feedback not found'}), 404
        
        status = request.form.get('status')
        if status not in ['pending', 'in_progress', 'resolved']:
            return jsonify({'success': False, 'message': 'Invalid status'}), 400
        
        result = mongo.db.feedback.update_one(
            {'_id': ObjectId(feedback_id)},
            {'$set': {'status': status}}
        )
        
        if result.modified_count > 0:
            return jsonify({
                'success': True,
                'message': 'Feedback status updated successfully'
            })
        return jsonify({
            'success': False,
            'message': 'No changes were made to the feedback'
        }), 200
    except Exception as e:
        app.logger.error(f"Error updating feedback status: {str(e)}")
        return jsonify({
            'success': False,
            'message': 'Error updating feedback status'
        }), 500

@app.route('/learning-corner')
@login_required
def learning_corner():
    user = mongo.db.users.find_one({'_id': ObjectId(session['user_id'])})
    
    # Get user's tutorial requests
    user_requests = list(mongo.db.tutorial_requests.find(
        {'user_id': ObjectId(session['user_id'])}
    ).sort('created_at', -1))
    
    return render_template('learning_corner.html', 
                         user=user,
                         user_requests=user_requests)

@app.route('/learning-corner/whatsapp')
@login_required
def whatsapp_guide():
    user = mongo.db.users.find_one({'_id': ObjectId(session['user_id'])})
    return render_template('guides/whatsapp_guide.html', user=user)

@app.route('/learning-corner/youtube')
@login_required
def youtube_guide():
    user = mongo.db.users.find_one({'_id': ObjectId(session['user_id'])})
    return render_template('guides/youtube_guide.html', user=user)

@app.route('/learning-corner/payments')
@login_required
def payments_guide():
    user = mongo.db.users.find_one({'_id': ObjectId(session['user_id'])})
    return render_template('guides/payments_guide.html', user=user)

@app.route('/learning-corner/social-media')
@login_required
def social_media_guide():
    user = mongo.db.users.find_one({'_id': ObjectId(session['user_id'])})
    return render_template('guides/social_media_guide.html', user=user)

@app.route('/learning-corner/smartphone')
@login_required
def smartphone_guide():
    user = mongo.db.users.find_one({'_id': ObjectId(session['user_id'])})
    return render_template('guides/smartphone_guide.html', user=user)

@app.route('/learning-corner/video-calls')
@login_required
def video_calls_guide():
    user = mongo.db.users.find_one({'_id': ObjectId(session['user_id'])})
    return render_template('guides/video_calls_guide.html', user=user)

@app.route('/submit_tutorial_request', methods=['POST'])
@login_required
def submit_tutorial_request():
    try:
        # Get form data
        topic = request.form.get('topic')
        category = request.form.get('category')
        description = request.form.get('description')
        difficulty = request.form.get('difficulty')
        platform = request.form.get('platform')
        additional_notes = request.form.get('additional_notes')

        # Get user details
        user = mongo.db.users.find_one({'_id': ObjectId(session['user_id'])})
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404

        # Create new tutorial request
        new_request = {
            'user_id': ObjectId(session['user_id']),
            'user_name': user['name'],
            'topic': topic,
            'category': category,
            'description': description,
            'difficulty': difficulty,
            'platform': platform,
            'additional_notes': additional_notes,
            'status': 'pending',
            'created_at': datetime.utcnow()
        }

        # Add to database
        result = mongo.db.tutorial_requests.insert_one(new_request)
        if result.inserted_id:
            return jsonify({'success': True, 'message': 'Tutorial request submitted successfully'})
        return jsonify({'success': False, 'message': 'Failed to submit tutorial request'}), 500
    except Exception as e:
        print(f"Error submitting tutorial request: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/admin/debug/tutorial_requests')
@login_required
def debug_tutorial_requests():
    if not session.get('is_admin'):
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        # Get raw data from MongoDB
        requests = list(mongo.db.tutorial_requests.find())
        
        # Convert ObjectId to string for JSON serialization
        for req in requests:
            req['_id'] = str(req['_id'])
            if 'user_id' in req:
                req['user_id'] = str(req['user_id'])
            if isinstance(req.get('created_at'), datetime):
                req['created_at'] = req['created_at'].strftime('%Y-%m-%d %H:%M')
        
        return jsonify({
            'count': len(requests),
            'requests': requests
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/admin/tutorial_requests')
@login_required
def admin_tutorial_requests():
    if not session.get('is_admin'):
        flash('Access denied. Admin privileges required.', 'error')
        return redirect(url_for('login'))
    
    try:
        # Get all tutorial requests
        requests = list(mongo.db.tutorial_requests.find())
        print(f"\nFound {len(requests)} tutorial requests in database")
        
        # Format requests for display
        formatted_requests = []
        for req in requests:
            # Convert ObjectId to string
            req['_id'] = str(req['_id'])
            if 'user_id' in req:
                req['user_id'] = str(req['user_id'])
            
            # Format datetime
            if isinstance(req.get('created_at'), datetime):
                req['created_at'] = req['created_at'].strftime('%Y-%m-%d %H:%M')
            
            formatted_requests.append(req)
        
        print(f"Formatted {len(formatted_requests)} requests for display")
        
        # Debug output
        print("\nFirst request data:")
        if formatted_requests:
            print(formatted_requests[0])
        
        return render_template('admin/tutorial_requests.html', requests=formatted_requests)
    except Exception as e:
        print(f"Error in admin_tutorial_requests: {str(e)}")
        flash('Error loading tutorial requests', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/tutorial_request/<request_id>/update', methods=['POST'])
@login_required
def update_tutorial_request(request_id):
    if not session.get('is_admin'):
        return jsonify({'success': False, 'message': 'Access denied'})
    
    try:
        data = request.get_json()
        tutorial_request = mongo.db.tutorial_requests.find_one({'_id': ObjectId(request_id)})
        
        if not tutorial_request:
            return jsonify({'success': False, 'message': 'Request not found'}), 404
        
        update_data = {
            'status': data.get('status', tutorial_request['status']),
            'admin_notes': data.get('admin_notes', tutorial_request.get('admin_notes', '')),
            'updated_at': datetime.utcnow()
        }
        
        result = mongo.db.tutorial_requests.update_one(
            {'_id': ObjectId(request_id)},
            {'$set': update_data}
        )
        
        if result.modified_count > 0:
            return jsonify({'success': True})
        return jsonify({'success': False, 'message': 'No changes were made to the request'}), 200
    except Exception as e:
        print(f"Error updating tutorial request: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/finance-management')
@login_required
def finance_management():
    try:
        user_id = ObjectId(session['user_id'])
        
        # Get current month's dates
        today = datetime.now()
        first_day = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        last_day = (today.replace(day=28) + timedelta(days=4)).replace(day=1) - timedelta(days=1)
        days_in_month = (last_day - first_day).days + 1
        
        # Get regular expenses for the current month
        regular_expenses = list(mongo.db.regular_expenses.find({
            'user_id': user_id,
            'date': {
                '$gte': first_day,
                '$lte': last_day
            }
        }).sort('date', -1))
        
        # Calculate regular expenses totals
        regular_total = sum(expense['amount'] for expense in regular_expenses)
        paid_regular_total = sum(expense['amount'] for expense in regular_expenses)
        pending_regular_total = 0  # All regular expenses are considered paid
        daily_regular_average = round(regular_total / days_in_month, 2)
        
        # Get fixed expenses
        fixed_expenses = list(mongo.db.fixed_expenses.find({
            'user_id': user_id
        }).sort('date', 1))
        
        # Calculate fixed expenses totals
        fixed_total = sum(expense['amount'] for expense in fixed_expenses if expense['frequency'] == 'monthly')
        paid_fixed_total = sum(expense['amount'] for expense in fixed_expenses if expense.get('is_paid', False))
        pending_fixed_total = fixed_total - paid_fixed_total
        daily_fixed_average = round(fixed_total / days_in_month, 2)
        
        # Calculate total monthly expenses
        total_monthly_expenses = regular_total + fixed_total
        total_paid_expenses = paid_regular_total + paid_fixed_total
        
        # Get recently paid regular expenses (last 5)
        paid_regular_expenses = list(mongo.db.regular_expenses.find({
            'user_id': user_id,
            'date': {
                '$gte': first_day,
                '$lte': last_day
            }
        }).sort('date', -1).limit(5))
        
        # Get recently paid fixed expenses (last 5)
        paid_fixed_expenses = list(mongo.db.fixed_expenses.find({
            'user_id': user_id,
            'is_paid': True
        }).sort('paid_at', -1).limit(5))
        
        return render_template('finance_management.html',
                             regular_total=regular_total,
                             fixed_total=fixed_total,
                             paid_regular_total=paid_regular_total,
                             paid_fixed_total=paid_fixed_total,
                             pending_regular_total=pending_regular_total,
                             pending_fixed_total=pending_fixed_total,
                             daily_regular_average=daily_regular_average,
                             daily_fixed_average=daily_fixed_average,
                             total_monthly_expenses=total_monthly_expenses,
                             total_paid_expenses=total_paid_expenses,
                             paid_regular_expenses=paid_regular_expenses,
                             paid_fixed_expenses=paid_fixed_expenses)
    except Exception as e:
        print(f"Error in finance_management: {str(e)}")
        flash('Error loading finance management page', 'error')
        return redirect(url_for('dashboard'))

@app.route('/regular-expenses')
@login_required
def regular_expenses():
    try:
        user_id = ObjectId(session['user_id'])
        
        # Get current month's expenses
        today = datetime.now()
        first_day = today.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        last_day = (today.replace(day=28) + timedelta(days=4)).replace(day=1) - timedelta(days=1)
        
        # Get all regular expenses for the current month
        expenses = list(mongo.db.regular_expenses.find({
            'user_id': user_id,
            'date': {
                '$gte': first_day,
                '$lte': last_day
            }
        }).sort('date', -1))
        
        # Calculate monthly total
        monthly_total = sum(expense['amount'] for expense in expenses)
        
        # Calculate daily average
        days_in_month = (last_day - first_day).days + 1
        daily_average = round(monthly_total / days_in_month, 2)
        
        # Calculate category-wise totals for pie chart
        category_totals = {}
        for expense in expenses:
            category = expense['category']
            if category not in category_totals:
                category_totals[category] = 0
            category_totals[category] += expense['amount']
        
        # Convert category totals to list format for the chart
        category_data = [
            {'category': category, 'amount': amount}
            for category, amount in category_totals.items()
        ]
        
        # Sort categories by amount (highest to lowest)
        category_data.sort(key=lambda x: x['amount'], reverse=True)
        
        # Find highest expense category
        highest_category = max(category_totals.items(), key=lambda x: x[1])[0] if category_totals else "No expenses"
        
        # Get user's monthly budget
        user = mongo.db.users.find_one({'_id': user_id})
        monthly_budget = user.get('monthly_budget', 0)
        remaining_budget = monthly_budget - monthly_total
        
        return render_template('regular_expenses.html',
                             expenses=expenses,
                             monthly_total=monthly_total,
                             daily_average=daily_average,
                             highest_category=highest_category,
                             remaining_budget=remaining_budget,
                             category_data=category_data,
                             total_amount=monthly_total)
    except Exception as e:
        print(f"Error in regular_expenses: {str(e)}")
        flash('Error loading expenses', 'error')
        return redirect(url_for('finance_management'))

@app.route('/add-regular-expense', methods=['POST'])
@login_required
def add_regular_expense():
    try:
        user_id = ObjectId(session['user_id'])
        
        # Get form data
        name = request.form.get('expenseName')
        amount = float(request.form.get('expenseAmount'))
        category = request.form.get('expenseCategory')
        description = request.form.get('expenseDescription')
        date = datetime.strptime(request.form.get('expenseDate'), '%Y-%m-%d')
        
        # Create expense document
        expense = {
            'user_id': user_id,
            'name': name,
            'amount': amount,
            'category': category,
            'description': description,
            'date': date,
            'created_at': datetime.utcnow()
        }
        
        # Insert into database
        result = mongo.db.regular_expenses.insert_one(expense)
        
        if result.inserted_id:
            flash('Expense added successfully!', 'success')
        else:
            flash('Error adding expense', 'error')
            
    except Exception as e:
        print(f"Error adding expense: {str(e)}")
        flash('Error adding expense', 'error')
        
    return redirect(url_for('regular_expenses'))

@app.route('/delete-expense/<expense_id>', methods=['POST'])
@login_required
def delete_expense(expense_id):
    try:
        user_id = ObjectId(session['user_id'])
        
        # Delete expense
        result = mongo.db.regular_expenses.delete_one({
            '_id': ObjectId(expense_id),
            'user_id': user_id
        })
        
        if result.deleted_count > 0:
            return jsonify({'success': True})
        return jsonify({'success': False, 'message': 'Expense not found'})
        
    except Exception as e:
        print(f"Error deleting expense: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/fixed-expenses')
@login_required
def fixed_expenses():
    try:
        user_id = ObjectId(session['user_id'])
        
        # Get all fixed expenses for the user
        expenses = list(mongo.db.fixed_expenses.find({
            'user_id': user_id
        }).sort('date', 1))
        
        # Calculate payment status and due date indicators
        today = datetime.now()
        for expense in expenses:
            # Convert string date to datetime if needed
            if isinstance(expense['date'], str):
                expense['date'] = datetime.strptime(expense['date'], '%Y-%m-%d')
            
            # Calculate days until due
            days_until_due = (expense['date'] - today).days
            
            # Set payment status indicators
            expense['is_paid'] = expense.get('is_paid', False)
            expense['is_overdue'] = days_until_due < 0 and not expense['is_paid']
            expense['is_due_soon'] = 0 <= days_until_due <= 3 and not expense['is_paid']
        
        # Calculate monthly total
        monthly_total = sum(expense['amount'] for expense in expenses if expense['frequency'] == 'monthly')
        
        # Calculate monthly average (including quarterly and yearly expenses)
        monthly_average = 0
        for expense in expenses:
            if expense['frequency'] == 'monthly':
                monthly_average += expense['amount']
            elif expense['frequency'] == 'quarterly':
                monthly_average += expense['amount'] / 3
            elif expense['frequency'] == 'yearly':
                monthly_average += expense['amount'] / 12
        
        monthly_average = round(monthly_average, 2)
        
        # Find highest expense category
        category_totals = {}
        for expense in expenses:
            category = expense['category']
            if expense['frequency'] == 'monthly':
                amount = expense['amount']
            elif expense['frequency'] == 'quarterly':
                amount = expense['amount'] / 3
            else:  # yearly
                amount = expense['amount'] / 12
            category_totals[category] = category_totals.get(category, 0) + amount
        
        highest_category = max(category_totals.items(), key=lambda x: x[1])[0] if category_totals else "No expenses"
        
        # Find next due date
        next_due = None
        for expense in expenses:
            if not expense['is_paid'] and expense['date'] > today:
                if next_due is None or expense['date'] < next_due:
                    next_due = expense['date']
        
        next_due_date = next_due.strftime('%B %d, %Y') if next_due else "No upcoming expenses"
        
        return render_template('fixed_expenses.html',
                             expenses=expenses,
                             monthly_total=monthly_total,
                             monthly_average=monthly_average,
                             highest_category=highest_category,
                             next_due_date=next_due_date)
    except Exception as e:
        print(f"Error in fixed_expenses: {str(e)}")
        flash('Error loading expenses', 'error')
        return redirect(url_for('finance_management'))

@app.route('/add-fixed-expense', methods=['POST'])
@login_required
def add_fixed_expense():
    try:
        user_id = ObjectId(session['user_id'])
        
        # Get form data
        name = request.form.get('expenseName')
        amount = float(request.form.get('expenseAmount'))
        category = request.form.get('expenseCategory')
        frequency = request.form.get('expenseFrequency')
        description = request.form.get('expenseDescription')
        date = datetime.strptime(request.form.get('expenseDate'), '%Y-%m-%d')
        
        # Create expense document
        expense = {
            'user_id': user_id,
            'name': name,
            'amount': amount,
            'category': category,
            'frequency': frequency,
            'description': description,
            'date': date,
            'created_at': datetime.utcnow()
        }
        
        # Insert into database
        result = mongo.db.fixed_expenses.insert_one(expense)
        
        if result.inserted_id:
            flash('Fixed expense added successfully!', 'success')
        else:
            flash('Error adding fixed expense', 'error')
            
    except Exception as e:
        print(f"Error adding fixed expense: {str(e)}")
        flash('Error adding fixed expense', 'error')
        
    return redirect(url_for('fixed_expenses'))

@app.route('/delete-fixed-expense/<expense_id>', methods=['POST'])
@login_required
def delete_fixed_expense(expense_id):
    try:
        user_id = ObjectId(session['user_id'])
        
        # Delete expense
        result = mongo.db.fixed_expenses.delete_one({
            '_id': ObjectId(expense_id),
            'user_id': user_id
        })
        
        if result.deleted_count > 0:
            return jsonify({'success': True})
        return jsonify({'success': False, 'message': 'Expense not found'})
        
    except Exception as e:
        print(f"Error deleting fixed expense: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/update-payment-status/<expense_id>', methods=['POST'])
@login_required
def update_payment_status(expense_id):
    try:
        user_id = ObjectId(session['user_id'])
        data = request.get_json()
        is_paid = data.get('is_paid', False)
        
        # Update payment status
        result = mongo.db.fixed_expenses.update_one(
            {
                '_id': ObjectId(expense_id),
                'user_id': user_id
            },
            {
                '$set': {
                    'is_paid': is_paid,
                    'paid_at': datetime.utcnow() if is_paid else None
                }
            }
        )
        
        if result.modified_count > 0:
            return jsonify({'success': True})
        return jsonify({'success': False, 'message': 'Expense not found'})
        
    except Exception as e:
        print(f"Error updating payment status: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/medicine-management')
@login_required
def medicine_management():
    try:
        user_id = ObjectId(session['user_id'])
        print(f"Fetching medicines for user_id: {user_id}")
        
        # Get all medicines for the user
        medicines = list(mongo.db.medicines.find({
            'user_id': user_id
        }).sort('name', 1))
        print(f"Found {len(medicines)} medicines in database")
        
        # Get today's medicine schedule
        today = datetime.now()
        today_start = datetime.combine(today.date(), datetime.min.time())
        today_end = datetime.combine(today.date(), datetime.max.time())
        print(f"Looking for medicines between {today_start} and {today_end}")
        
        today_medicines = list(mongo.db.medicine_schedule.find({
            'user_id': user_id,
            'date': {
                '$gte': today_start,
                '$lte': today_end
            },
            'is_taken': False
        }).sort('time', 1))
        print(f"Found {len(today_medicines)} medicines scheduled for today")
        
        # Get taken medicines for today
        taken_medicines = list(mongo.db.medicine_schedule.find({
            'user_id': user_id,
            'date': {
                '$gte': today_start,
                '$lte': today_end
            },
            'is_taken': True
        }).sort('time', 1))
        print(f"Found {len(taken_medicines)} medicines taken today")
        
        # Get any pending notifications for this page
        notification = session.pop('medicine_notification', None)
        
        return render_template('medicine_management.html',
                             medicines=medicines,
                             today_medicines=today_medicines,
                             taken_medicines=taken_medicines,
                             notification=notification)
    except Exception as e:
        print(f"Error in medicine_management: {str(e)}")
        session['medicine_notification'] = {'type': 'error', 'message': 'Error loading medicine management page'}
        return redirect(url_for('dashboard'))

@app.route('/add-medicine', methods=['POST'])
@login_required
def add_medicine():
    try:
        user_id = ObjectId(session['user_id'])
        print(f"Adding medicine for user_id: {user_id}")
        
        # Get form data
        name = request.form.get('medicineName')
        dosage = request.form.get('dosage')
        frequency = request.form.get('frequency')
        times = request.form.getlist('times[]')
        days = request.form.getlist('days')
        notes = request.form.get('notes')
        
        print(f"Received medicine data: name={name}, dosage={dosage}, frequency={frequency}")
        print(f"Times: {times}, Days: {days}")
        
        if not times:
            session['medicine_notification'] = {'type': 'error', 'message': 'Please provide at least one time for the medicine'}
            return redirect(url_for('medicine_management'))
        
        if not days:
            session['medicine_notification'] = {'type': 'error', 'message': 'Please select at least one day'}
            return redirect(url_for('medicine_management'))
        
        # Create medicine document
        medicine = {
            'user_id': user_id,
            'name': name,
            'dosage': dosage,
            'frequency': frequency,
            'times': times,
            'days': days,
            'notes': notes,
            'created_at': datetime.utcnow()
        }
        
        # Insert into database
        result = mongo.db.medicines.insert_one(medicine)
        print(f"Inserted medicine with ID: {result.inserted_id}")
        
        if result.inserted_id:
            # Create schedule entries for the next 30 days
            schedule_entries = []
            start_date = datetime.now().date()
            
            for i in range(30):
                current_date = start_date + timedelta(days=i)
                day_name = current_date.strftime('%A').lower()
                
                if day_name in days:
                    for time_str in times:
                        time_obj = datetime.strptime(time_str, '%H:%M').time()
                        schedule_datetime = datetime.combine(current_date, time_obj)
                        
                        schedule_entries.append({
                            'user_id': user_id,
                            'medicine_id': result.inserted_id,
                            'medicine_name': name,
                            'dosage': dosage,
                            'time': time_str,
                            'date': schedule_datetime,
                            'is_taken': False,
                            'created_at': datetime.utcnow()
                        })
            
            if schedule_entries:
                print(f"Creating {len(schedule_entries)} schedule entries")
                schedule_result = mongo.db.medicine_schedule.insert_many(schedule_entries)
                print(f"Inserted {len(schedule_result.inserted_ids)} schedule entries")
            
            session['medicine_notification'] = {'type': 'success', 'message': 'Medicine added successfully!'}
        else:
            session['medicine_notification'] = {'type': 'error', 'message': 'Error adding medicine'}
            
    except Exception as e:
        print(f"Error adding medicine: {str(e)}")
        session['medicine_notification'] = {'type': 'error', 'message': 'Error adding medicine'}
        
    return redirect(url_for('medicine_management'))

@app.route('/update-medicine-status/<schedule_id>', methods=['POST'])
@login_required
def update_medicine_status(schedule_id):
    try:
        user_id = ObjectId(session['user_id'])
        data = request.get_json()
        is_taken = data.get('is_taken', False)
        
        # Update medicine status
        result = mongo.db.medicine_schedule.update_one(
            {
                '_id': ObjectId(schedule_id),
                'user_id': user_id
            },
            {
                '$set': {
                    'is_taken': is_taken,
                    'taken_at': datetime.utcnow() if is_taken else None
                }
            }
        )
        
        if result.modified_count > 0:
            return jsonify({'success': True})
        return jsonify({'success': False, 'message': 'Medicine schedule not found'})
        
    except Exception as e:
        print(f"Error updating medicine status: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/delete-medicine/<medicine_id>', methods=['POST'])
@login_required
def delete_medicine(medicine_id):
    try:
        user_id = ObjectId(session['user_id'])
        
        # Delete medicine and its schedule
        mongo.db.medicines.delete_one({
            '_id': ObjectId(medicine_id),
            'user_id': user_id
        })
        
        mongo.db.medicine_schedule.delete_many({
            'medicine_id': ObjectId(medicine_id),
            'user_id': user_id
        })
        
        return jsonify({'success': True})
        
    except Exception as e:
        print(f"Error deleting medicine: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/reminders')
@login_required
def reminders():
    try:
        user_id = ObjectId(session['user_id'])
        now = datetime.now()
        today = now.date()
        tomorrow = today + timedelta(days=1)
        day_after = today + timedelta(days=2)

        # Next 2 days reminders
        next_two_days = list(mongo.db.reminders.find({
            'user_id': user_id,
            'completed': False,
            'date': {'$gte': today.strftime('%Y-%m-%d'), '$lte': day_after.strftime('%Y-%m-%d')}
        }).sort([('date', 1), ('time', 1)]))

        # Upcoming reminders (after next 2 days)
        upcoming = list(mongo.db.reminders.find({
            'user_id': user_id,
            'completed': False,
            'date': {'$gt': day_after.strftime('%Y-%m-%d')}
        }).sort([('date', 1), ('time', 1)]))

        # Completed reminders
        completed = list(mongo.db.reminders.find({
            'user_id': user_id,
            'completed': True
        }).sort([('completed_at', -1)]))

        # Get any pending notifications for this page
        notification = session.pop('reminder_notification', None)

        return render_template('reminders.html', 
                             next_two_days=next_two_days, 
                             upcoming=upcoming, 
                             completed=completed,
                             notification=notification)
    except Exception as e:
        print(f"Error in reminders route: {str(e)}")
        session['reminder_notification'] = {'type': 'error', 'message': 'Error loading reminders'}
        return redirect(url_for('dashboard'))

@app.route('/add-reminder', methods=['POST'])
@login_required
def add_reminder():
    try:
        user_id = ObjectId(session['user_id'])
        title = request.form.get('title')
        description = request.form.get('description')
        date = request.form.get('date')
        time = request.form.get('time')
        
        if not (title and date and time):
            session['reminder_notification'] = {'type': 'error', 'message': 'Title, date, and time are required!'}
            return redirect(url_for('reminders'))
            
        reminder = {
            'user_id': user_id,
            'title': title,
            'description': description,
            'date': date,
            'time': time,
            'completed': False,
            'created_at': datetime.utcnow()
        }
        
        result = mongo.db.reminders.insert_one(reminder)
        if result.inserted_id:
            session['reminder_notification'] = {'type': 'success', 'message': 'Reminder added successfully!'}
        else:
            session['reminder_notification'] = {'type': 'error', 'message': 'Error adding reminder'}
            
    except Exception as e:
        print(f"Error adding reminder: {str(e)}")
        session['reminder_notification'] = {'type': 'error', 'message': 'Error adding reminder'}
        
    return redirect(url_for('reminders'))

@app.route('/complete-reminder/<reminder_id>', methods=['POST'])
@login_required
def complete_reminder(reminder_id):
    user_id = ObjectId(session['user_id'])
    result = mongo.db.reminders.update_one(
        {'_id': ObjectId(reminder_id), 'user_id': user_id},
        {'$set': {'completed': True, 'completed_at': datetime.utcnow()}}
    )
    if result.modified_count > 0:
        return jsonify({'success': True})
    return jsonify({'success': False, 'message': 'Reminder not found or already completed'})

@app.route('/delete-reminder/<reminder_id>', methods=['POST'])
@login_required
def delete_reminder(reminder_id):
    try:
        user_id = ObjectId(session['user_id'])
        result = mongo.db.reminders.delete_one({
            '_id': ObjectId(reminder_id),
            'user_id': user_id
        })
        
        if result.deleted_count > 0:
            return jsonify({'success': True})
        return jsonify({'success': False, 'message': 'Reminder not found'})
    except Exception as e:
        print(f"Error deleting reminder: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/create-emergency-log', methods=['POST'])
@login_required
def create_emergency_log():
    try:
        data = request.get_json()
        if not data or 'contact_type' not in data or 'phone_number' not in data:
            return jsonify({'success': False, 'message': 'Missing required fields'}), 400

        user = mongo.db.users.find_one({'_id': ObjectId(session['user_id'])})
        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404

        # Create emergency log
        log = {
            'user_id': ObjectId(session['user_id']),
            'user_name': user['name'],
            'contact_type': data['contact_type'],
            'phone_number': data['phone_number'],
            'created_at': datetime.utcnow()
        }

        # If user is an elder, add linked child info
        if user['role'] == 'elder':
            linked_child = mongo.db.users.find_one({
                'elder_id': str(user['_id']),
                'role': 'child'
            })
            if linked_child:
                log['linked_child_id'] = linked_child['_id']
                log['linked_child_name'] = linked_child['name']

        result = mongo.db.emergency_logs.insert_one(log)
        if result.inserted_id:
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'message': 'Failed to create emergency log'}), 500

    except Exception as e:
        print(f"Error creating emergency log: {str(e)}")
        return jsonify({'success': False, 'message': 'Error creating emergency log'}), 500

if __name__ == '__main__':
    app.run(debug=True) 