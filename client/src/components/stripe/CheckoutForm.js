import React, { Component } from 'react';
import { CardElement, injectStripe } from 'react-stripe-elements';
import axios from 'axios';
import { connect } from 'react-redux';
import { addSub, addCredit } from '../../actions/stripe';

const subCost = 2000;
const invoiceCost = 199;

// const token = localStorage.getItem('id');
axios.defaults.headers.common.Authorization = 'bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI1YjUyMzUyYWM5MGNkYTEyOTZhYWRiNzciLCJpYXQiOjE1MzIxMTQyMTg1MzAsInVzZXJuYW1lIjoiMkB0ZXN0LmNvbSIsImV4cCI6MTUzMjIwMDYxODUzMH0.fBddrd-xjv3pDBwA85LnGgWsCLwipFTX0JZoHk9IBHs';

class CheckoutForm extends Component {
  constructor(props) {
    super(props);
    this.submit = this.submit.bind(this);
    this.state = {
      amount: 50,
    };
  }

  async submit(ev) {
    // User clicked submit
    const { token } = await this.props.stripe.createToken({ name: 'Name' });
    console.log(token.id);
    // const response = await fetch('/charge', {
    //   method: 'POST',
    //   headers: { 'Content-Type': 'text/plain' },
    //   body: token.id,
    // });

    // if (response.ok) console.log('Purchase Complete!');
    axios
      .post('http://localhost:5000/api/charge', {
        type: 'sub',
        units: 30,
        id: token.id,
        amount: this.state.amount,
      })
      .then(response => {
        console.log(response);
      })
      .catch(err => console.log(err));
  }

  render() {
    return (
      <div className="checkout">
        <p>Would you like to complete the purchase?</p>
        <CardElement />
        <button onClick={this.submit}>Send</button>
      </div>
    );
  }
}

export default connect(
  null,
  { addSub, addCredit },
)(injectStripe(CheckoutForm));
