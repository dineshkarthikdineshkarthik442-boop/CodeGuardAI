import React from 'react';
import {createRoot} from 'react-dom/client';
import App from './App';
class ErrorBoundary extends React.Component {
 constructor(props){super(props);this.state={error:false}}
 static getDerivedStateFromError(){return {error:true}}
 render(){return this.state.error?<div style={{padding:40,color:'#eef3ff',background:'#070b14'}}><h1>CodeGuard could not display this page.</h1><p>Refresh the page. If it continues, check the browser console and server windows.</p><button onClick={()=>location.reload()}>Reload</button></div>:this.props.children}
}
createRoot(document.getElementById('root')).render(<React.StrictMode><ErrorBoundary><App/></ErrorBoundary></React.StrictMode>);
