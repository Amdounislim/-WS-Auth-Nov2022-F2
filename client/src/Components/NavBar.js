import React from 'react'
import { useDispatch, useSelector } from 'react-redux'
import { Link } from 'react-router-dom'
import { logout } from '../JS/actions/userActions'

const NavBar = () => {

    const isAuth = useSelector(state => state.userReducer.isAuth)

    const dispatch = useDispatch()


    return (
        <div>
            {isAuth ? (<nav className="navbar navbar-expand-lg navbar-light fixed-top">
                <div className="container">
                    <Link className="navbar-brand" to={"/login"}>
                        Authentification Passport
                    </Link>
                    <div className="collapse navbar-collapse" id="navbarTogglerDemo02">
                        <ul className="navbar-nav ml-auto">
                            <li className="nav-item">
                                <Link className="nav-link" to={"/"} onClick={() => dispatch(logout())}>
                                    LOGOUT
                                </Link>
                            </li>
                        </ul>
                    </div>
                </div>
            </nav>)
                : (<nav className="navbar navbar-expand-lg navbar-light fixed-top">
                    <div className="container">
                        <Link className="navbar-brand" to={"/login"}>
                            Authentification Passport
                        </Link>
                        <div className="collapse navbar-collapse" id="navbarTogglerDemo02">
                            <ul className="navbar-nav ml-auto">
                                <li className="nav-item">
                                    <Link className="nav-link" to={"/login"}>
                                        Sign in
                                    </Link>
                                </li>
                                <li className="nav-item">
                                    <Link className="nav-link" to={"/register"}>
                                        Sign up
                                    </Link>
                                </li>
                            </ul>
                        </div>
                    </div>
                </nav>)}
        </div>
    )
}

export default NavBar