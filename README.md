Online Property Rental and Management Portal
About the Project

The Online Property Rental and Management Portal is a web application developed using Python Flask. The main purpose of this project is to make property rental and management activities easier for property owners and tenants.

Instead of managing rental details manually, users can use this application to handle property listings, rental applications, lease details, rent payments, complaints, and maintenance requests in one place.

The application has separate access for Admin, Property Owners, and Tenants. Each user can access the features based on their role.

Features

 1. User Registration and Login
- Separate registration for property owners and tenants.
- Secure login and logout.
- Password hashing for better security.
- Role-based access control.

2. Admin Dashboard
- View registered users.
- View property owners and tenants.
- Monitor property listings.
- View rental applications.
- Monitor payments, leases, complaints, and maintenance requests.
- View overall project statistics.

 3. Property Owner Features
- Add new rental properties.
- Edit existing property details.
- Delete property listings.
- Upload multiple property images.
- View rental applications.
- Manage tenant lease details.
- View payment information.
- Handle tenant complaints and maintenance requests.

4. Tenant Features
- View available rental properties.
- Search properties by location.
- Filter properties by type and rent range.
- Apply for rental properties.
- View application status.
- View active lease details.
- View monthly rent information.
- Access QR code payment details.
- Submit complaints.
- Submit maintenance requests.

5. Rental and Lease Management
- Create and manage lease records.
- Store lease start and end dates.
- Maintain monthly rent details.
- Track active and completed lease information.

6. Payment Management
- Display monthly rental amount.
- Provide QR code payment details.
- Store payment records.
- Track payment status.
- Support payment verification details.

7. Complaint Management
- Tenants can submit complaints related to their rented properties.
- Owners and administrators can view complaint records.
- Complaint details and status can be maintained.

8. Maintenance Management
- Tenants can report maintenance issues.
- Owners can view maintenance requests.
- Maintenance status can be updated.

9. Profile Management
- View and update personal information.
- Update contact details and address.
- Upload and update profile pictures.

10. Tenant Document Management
- Upload tenant documents.
- Supported document types include ID Proof, PAN Card, Rental Agreement, Income Proof, and Other.
- Download uploaded documents.
- Delete uploaded documents.

 11. Security
- Password hashing.
- Session-based authentication.
- Role-based authorization.
- CSRF protection for protected form submissions.
- File type and file size validation.
- Secure filenames for uploaded files.

Technologies Used

- Frontend: HTML, CSS, JavaScript
- Backend: Python, Flask
- Database:SQLite
- Template Engine: Jinja2
- Security: Werkzeug Password Hashing
- Version Control:GitHub

installation and Setup

Step 1: Clone the Repository

git clone YOUR_GITHUB_REPOSITORY_URL

Step 2: Open the Project Folder

cd Online-Property-Rental-Management-Portal

Step 3: Create a Virtual Environment

python -m venv venv

Activate the virtual environment.

Windows:

venv\Scripts\activate

Mac/Linux:

source venv/bin/activate

Step 4: Install Required Packages

pip install Flask

Step 5: Set Environment Variables

For Windows Command Prompt:

set FLASK_SECRET_KEY=your_secret_key
set ADMIN_EMAIL=admin@gmail.com
set ADMIN_PASSWORD=your_admin_password

For Mac/Linux:

export FLASK_SECRET_KEY=your_secret_key
export ADMIN_EMAIL=admin@gmail.com
export ADMIN_PASSWORD=your_admin_password

Use your own secret key and a strong admin password. Do not upload these values to GitHub.

Step 6: Run the Application

python app.py

Open your browser and visit:

http://127.0.0.1:5000/

The application will create the SQLite database and required tables when its database initialization function runs.




Database

This project uses SQLite to store application information.

The database contains tables for:

- Users
- Properties
- Property Images
- Applications
- Payments
- Complaints
- Leases
- Maintenance
- Tenant Documents

Future Improvements

- Online payment gateway integration.
- Email and SMS notifications.
- Advanced property search.
- Rental agreement PDF generation.
- Improved reporting and analytics.

Conclusion

This project helped me understand how a web-based rental management system can be developed using Python Flask and SQLite. It brings the main activities of property owners and tenants together in one application and makes rental management more organized and convenient.

## Author

Developed as an academic project.
