from flask import Flask, render_template, request, redirect, flash
from ldap3 import Server, Connection, ALL, SIMPLE, Tls
import ssl
from ldap3.core.exceptions import LDAPBindError, LDAPException
import os
from dotenv import load_dotenv

# Load environment variables from a .env file for local development
load_dotenv()

app = Flask(__name__)
# It's highly recommended to set the SECRET_KEY in your environment for production.
app.secret_key = os.getenv('SECRET_KEY', 'a-default-secret-key-for-dev')


# Active Directory configuration from environment variables
AD_SERVER_IP = os.getenv('AD_SERVER_IP')
AD_DOMAIN = os.getenv('AD_DOMAIN')
AD_FQDN = os.getenv('AD_FQDN')
AD_ADMIN_USERNAME = os.getenv('AD_ADMIN_USERNAME', 'Administrator')
AD_ADMIN_PASS = os.getenv('AD_ADMIN_PASS')

# Check if critical variables are set, otherwise raise an error
if not all([AD_SERVER_IP, AD_DOMAIN, AD_FQDN, AD_ADMIN_PASS]):
    raise ValueError("Please set required environment variables: AD_SERVER_IP, AD_DOMAIN, AD_FQDN, AD_ADMIN_PASS.")

# Construct derived configuration values
AD_ADMIN_USER = f'{AD_DOMAIN}\\{AD_ADMIN_USERNAME}'
SEARCH_BASE = f"DC={AD_FQDN.replace('.', ',DC=')}"

tls_configuration = Tls(validate=ssl.CERT_NONE)

@app.route('/', methods=['GET', 'POST'])
def change_password():
    if request.method == 'POST':
        username = request.form['username']
        current_password = request.form['current_password']
        new_password = request.form['new_password']
        confirm_password = request.form['confirm_password']

        if new_password != confirm_password:
            flash('New password and confirm password do not match.', 'danger')
            return redirect('/')

        server = Server(AD_SERVER_IP, port=636, use_ssl=True, get_info=ALL, tls=tls_configuration)

        allow_password_change = False
        diagnostic_message = ''

        try:
            user_principal = f"{AD_DOMAIN}\\{username}"
            print(f"Trying to bind as: {user_principal}")
            user_conn = Connection(server, user=user_principal, password=current_password, authentication=SIMPLE, auto_bind=True)
            user_conn.unbind()
            allow_password_change = True  # password is correct and active
            print("User bind successful. Password is valid and not expired.")
        except LDAPBindError as e:
            print("User bind failed:", e)
            # Manually try bind to inspect the diagnostic message
            conn = Connection(server, user=user_principal, password=current_password, authentication=SIMPLE)
            conn.bind()
            print("Bind result:", conn.result)
            diagnostic_message = conn.result.get('message') or ''
            description = conn.result.get('description') or ''
            print("Diagnostic message:", diagnostic_message)
            print("Description:", description)

            # Check if password expired error
            if "532" in diagnostic_message or "701" in diagnostic_message or "773" in diagnostic_message:
                print("Password expired but correct.")
                allow_password_change = True
            else:
                flash('Authentication failed: current password incorrect.', 'danger')
                return redirect('/')

        if allow_password_change:
            admin_conn = None
            try:
                admin_conn = Connection(server, user=AD_ADMIN_USER, password=AD_ADMIN_PASS, authentication=SIMPLE, auto_bind=True)
                print("Admin bind successful.")
                admin_conn.search(SEARCH_BASE, f'(sAMAccountName={username})', attributes=['distinguishedName'])
                if not admin_conn.entries:
                    flash('User not found in Active Directory.', 'danger')
                    return redirect('/')

                user_dn_full = admin_conn.entries[0].entry_dn
                print(f"Found user DN: {user_dn_full}")

                # modify_password returns True on success, False on failure
                if admin_conn.extend.microsoft.modify_password(user_dn_full, new_password):
                    flash('Password successfully changed.', 'success')
                else:
                    # On failure, the error message is in the connection result
                    error_message = admin_conn.result.get('message', 'An unknown error occurred.')
                    print(f"Password change failed. AD Message: {error_message}")
                    if 'constraint violation' in error_message.lower():
                        flash('Password change failed: New password does not meet complexity requirements.', 'danger')
                    elif 'unwilling to perform' in error_message.lower():
                        flash('Password change failed: New password may be one of the recently used passwords.', 'danger')
                    else:
                        flash(f'Failed to change password: {error_message}', 'danger')
                
                return redirect('/')
            except LDAPException as e:
                print(f"An LDAP error occurred during password change: {e}")
                flash(f'A directory service error occurred: {str(e)}', 'danger')
                return redirect('/')
            except Exception as e:
                print(f"An unexpected error occurred during password change: {e}")
                flash(f'An unexpected error occurred: {str(e)}', 'danger')
                return redirect('/')
            finally:
                if admin_conn and admin_conn.bound:
                    admin_conn.unbind()
                    print("Admin connection unbound.")

    return render_template('change_password.html')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
