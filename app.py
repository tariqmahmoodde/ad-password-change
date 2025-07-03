from flask import Flask, render_template, request, redirect, flash
from ldap3 import Server, Connection, ALL, SIMPLE, Tls
import ssl
from ldap3.core.exceptions import LDAPBindError, LDAPException

app = Flask(__name__)
app.secret_key = 'supersecret'  # move to env var in production

# Active Directory configuration
AD_SERVER_IP = '172.30.20.200'
AD_DOMAIN = 'OCTA'
AD_FQDN = 'octa.local'
AD_ADMIN_USER = f'{AD_DOMAIN}\\Administrator'
AD_ADMIN_PASS = 'ShineSt@r#'
SEARCH_BASE = 'DC=octa,DC=local'

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
