# Portal Mbk Tech Studio

**Note:** For an enhanced editing experience in Visual Studio Code, install the `Nunjucks Templates` extension to better view and edit `.njk` files.

## To Do
 - In Donation Page find if folder is created with name of user name if exist then show detail and tell you already have history
 - in table submit path of system img path not client
 - return total amount on donation.njk by summing all confirmed trnsactions
 - add donation page in main pages/sidebar
 - make list pages so user can find them

## Other Info

 - Feedback is Save In public/Assets/feedback.json
 - Donation proof img is save in (../repo)/donation/<username>/ 

## Roles & Permission Access Management

- `checkRestrictionFromTable`: This function checks if the user is restricted from accessing a page or making a post request.
- `checkRolePermission(Role)`: This function checks if the user's role matches the function parameter. If not, the user is denied permission.
- `checkRoleRestriction(Role, RequiredRole)`: This function checks if the user's role matches the required role. If yes, the user is denied permission.

## Cookies Used In App

*Note:* All previously saved cookies are reset/destroyed when the user logs out or logs in.

Currently, the app saves and uses three known cookies:
- `username`: Used in the header profile menu and on the login page to display the username. Changing it won't affect the username in the user profile or any permissions, so it's safe to use. It's just used to display the username where passing the value from the backend may be cumbersome and unnecessary.
- `userRole`: Used to check if user is SuperAdmin and hide notification. Changing `Role` in cookie won't do anything
- `donationNotice`: Checks if the user has seen the donation notice once. It refreshes when the user logs in or logs out.

You may also see the `agreed` cookie if you have visited mbktechstudio.com or its other subdomains and accepted the terms and conditions. However, this cookie is not used on this subdomain.

## Database Connection

The database connection is configured in `routes/pool.js`.

### Database Structure
The database consists of two tables: `Users` and `session`.


#### Users Table
- **Columns:**
  - `id` (INTEGER, auto-increment, primary key)
  - `UserName` (TEXT)
  - `FullName` (TEXT)
  - `Password` (TEXT)
  - `Role` (TEXT)  
    Values: `SuperAdmin`, `NormalAdmin`, `NormalUser`, `Guest`,`Demo`
  - `Active` (BOOLEAN)
  - `HaveMailAccount` (BOOLEAN)
  - `SessionId` (TEXT)

#### Session Table
- **Columns:**
  - `sid` (VARCHAR, primary key)
  - `sess` (JSON)
  - `expire` (TIMESTAMP)


## Frontend

The frontend is built using **Nunjucks**, a template syntax similar to HTML but with added logic.

### Example: Rendering Data


#### Backend (Node.js)
```javascript
res.render("mainPages/home.njk", {
    user: req.session.user,
    superAdmin: user.Role,
});
```

#### Frontend (Nunjucks)
```html
<p class="p">User: "{{ user.username }}, a {{ superAdmin }}"</p>

{% if superAdmin == "Guest" %}
    {% include "../notice/subAdmin.njk" %}
{% endif %}
```

## API Endpoints

### GET Requests

- `/` (home page / root page / landing page)
- `/login`
- `/home`
- `/user/profile`
- `/dashboard/Roles&Members`

### API GET JSON Requests
- `/api/feedback`


### POST Requests

- `/login`
- `/logout`
- `/terminateAllSessions`
- `/post/submitFeedback`

## Installation and Run

To install the necessary dependencies, run:

```bash
npm install
```

## Running the Application

To start the application, run:

```bash
node index.js
```

## License
 
This project is private and the source code is strictly prohibited from being shared.

See the [LICENSE](LICENSE.md) file for details.
 
## Contact

For questions or contributions, please contact Muhammad Bin Khalid at [mbktechstudio.com/Support](https://mbktechstudio.com/Support/), [support@mbktechstudio.com](mailto:support@mbktechstudio.com) or [chmuhammadbinkhalid28.com](mailto:chmuhammadbinkhalid28.com).