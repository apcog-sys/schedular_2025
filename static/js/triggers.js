function trigger( name, action, status){
    if (status==""){status="Done";}
    else{status="Failed"+status;}
    console.log("Note: ", name, action, status)
    return
}
