# AgeWell - A Smart Portal for Senior Citizen Support

AgeWell is a comprehensive web-based platform designed to empower elderly individuals by providing an intuitive interface for managing their social, financial, and health-related needs. The platform facilitates secure connections between seniors and their family members, enabling real-time monitoring and quick response during emergencies.

## 🌟 Key Features

### For Senior Citizens
- **Social Events & Community Interaction**
  - Browse and join local community events
  - Connect with peers through interest-based groups
  - Share experiences and stories in a safe environment

- **Learning Corner (Tech Literacy Hub)**
  - Easy-to-follow tutorials for common digital tools
  - Interactive guides for using smartphones and tablets
  - Regular workshops on digital safety and privacy

- **Personal Finance Manager**
  - Track daily expenses and income
  - Set up bill payment reminders
  - Monitor savings and investments
  - Generate monthly financial reports

- **Emergency Support System**
  - One-click emergency alert button
  - Real-time location sharing with family
  - Direct connection to emergency services
  - Automated notifications to registered contacts

- **Health & Wellness**
  - Daily health tips and wellness reminders
  - Medication tracking and reminders
  - Exercise and activity suggestions
  - Health metrics monitoring

### For Family Members
- **Remote Monitoring**
  - Real-time activity tracking
  - Health status updates
  - Emergency alerts and notifications
  - Location tracking (with consent)

- **Communication Tools**
  - Secure messaging system
  - Video call integration
  - Shared calendar for appointments
  - Family group chat

## 🛠️ Tech Stack

### Frontend
- HTML5, CSS3, Bootstrap 5
- JavaScript (ES6+)
- Jinja2 Templates
- Chart.js for data visualization
- FullCalendar.js for event management
- Google Maps API for location services

### Backend
- Flask 3.0.2 (Python)
- MongoDB 4.6.1 (Database)
- Flask-Login for authentication
- Flask-Mail for email notifications
- Twilio for SMS alerts
- APScheduler for task scheduling

### Security
- Bcrypt for password hashing
- Flask-Login for session management
- Environment variables for sensitive data
- CSRF protection
- Input validation and sanitization

## 🚀 Setup Instructions

1. **Prerequisites**
   - Python 3.8 or higher
   - MongoDB 4.4 or higher
   - Git
   - Virtual environment tool (venv)

2. **Clone the Repository**
   ```bash
   git clone https://github.com/Rakshitgupta9/AgeWell-A-Smart-Portal-for-Senior-Citizen-Support.git
   cd agewell
   ```

3. **Set Up Virtual Environment**
   ```bash
   # Windows
   python -m venv venv
   venv\Scripts\activate

   # Linux/MacOS
   python3 -m venv venv
   source venv/bin/activate
   ```

4. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

5. **Environment Configuration**
   Create a `.env` file in the root directory:
   ```
   # Application
   SECRET_KEY=your-secret-key
   FLASK_ENV=development
   FLASK_APP=run.py

   # Database
   MONGO_URI=mongodb://localhost:27017/agewell

   # Email Configuration
   MAIL_SERVER=smtp.gmail.com
   MAIL_PORT=587
   MAIL_USE_TLS=True
   MAIL_USERNAME=your-email@gmail.com
   MAIL_PASSWORD=your-app-password

   # Twilio Configuration
   TWILIO_ACCOUNT_SID=your-twilio-sid
   TWILIO_AUTH_TOKEN=your-twilio-token
   TWILIO_PHONE_NUMBER=your-twilio-phone

   # Google Maps API
   GOOGLE_MAPS_API_KEY=your-google-maps-api-key
   ```

6. **Database Setup**
   ```bash
   # Start MongoDB service
   # Windows
   net start MongoDB

   # Linux
   sudo systemctl start mongod

   # MacOS
   brew services start mongodb-community
   ```

7. **Run the Application**
   ```bash
   python run.py
   ```
   The application will be available at `http://localhost:5000`

## 📁 Project Structure

```
agewell/
├── app.py                    # Main Flask application file
├── requirements.txt          # Python dependencies
├── README.md                # Project documentation
├── templates/               # HTML templates
│   ├── admin/
│   │   └── feedback.html
│   ├── guides/
│   │   ├── video_calls_guide.html
│   │   ├── social_media_guide.html
│   │   ├── youtube_guide.html
│   │   ├── smartphone_guide.html
│   │   ├── payments_guide.html
│   │   └── whatsapp_guide.html
│   ├── profile.html
│   ├── base.html
│   ├── index.html
│   ├── register.html
│   ├── login.html
│   ├── dashboard.html
│   ├── admin_dashboard.html
│   ├── medicine_management.html
│   ├── social_events.html
│   ├── child_dashboard.html
│   ├── reminders.html
│   ├── learning_corner.html
│   ├── finance_management.html
│   ├── fixed_expenses.html
│   ├── regular_expenses.html
│   ├── admin_user_details.html
│   └── view_event.html
└── static/                  # Static assets
    ├── uploads/            # User uploaded files
    ├── css/               # Stylesheets
    ├── images/            # Image assets
    └── fonts/             # Font files
```

## 🤝 Contributing

We welcome contributions to AgeWell! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Development Guidelines
- Follow PEP 8 style guide for Python code
- Write meaningful commit messages
- Add tests for new features
- Update documentation as needed
- Ensure all tests pass before submitting PR

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Icons provided by [Font Awesome](https://fontawesome.com/)
- Maps integration powered by [Google Maps API](https://developers.google.com/maps)
- Charts and visualizations by [Chart.js](https://www.chartjs.org/)
- Calendar functionality by [FullCalendar](https://fullcalendar.io/)

## 📞 Support

For support, please email guptarakshit9858@gmail.com or open an issue in the GitHub repository. 
