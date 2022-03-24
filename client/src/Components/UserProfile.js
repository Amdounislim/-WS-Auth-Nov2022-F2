import React from 'react'

const UserProfile = () => {
  return (
    <div className="auth-wrapper">
      <div className="auth-inner">
        <div className="d-flex flex-column align-items-center text-center">
          <img
            src="https://bootdey.com/img/Content/avatar/avatar7.png"
            alt="Admin"
            className="rounded-circle"
            width="150"
          />
          <div className="mt-3">
            <h4></h4>
            <p className="text-secondary mb-1"></p>
            <p className="text-secondary mb-1">Full Stack Developer</p>
            <p className="text-muted font-size-sm"></p>
            <button className="btn btn-primary">Follow</button>
            <button className="btn btn-outline-primary">Message</button>
          </div>
        </div>
      </div>
    </div>
  )
}

export default UserProfile