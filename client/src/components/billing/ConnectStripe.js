import React, { Component } from 'react';

export default class ConnectStripe extends Component {
  state = { terms: false };

  render() {
    return (
      <div
        style={{
          margin: 20,
          width: '100%',
          height: '100%',
        }}
      >
        <h1 className="billing-title">Pricing:</h1>
        <h2 className="billing-purchase">$20 for a 30 day subscription.</h2>

        <p className="billing-label" style={{ marginLeft: 15 }}>
          This will allow an unlimited number of invoices and notifications to be set up until your
          subscription expires.
        </p>
        <h2 className="billing-purchase">$1.99 per invoice</h2>
        <p className="billing-label" style={{ marginLeft: 15 }}>
          Don't need a subscription? Easily use our service on a per invoice basis. $1.99 per
          invoice will include unlimited reminders for 1 invoice.
        </p>
        <br />
        <p className="billing-label">
          Before buying credits, you must connect your payMe account with a stripe account. This
          allows you clients to pay you directly. Once your client pays, 95% will be deposited into
          your stripe account immediately. You can then transfer to a bank acocunt of your choice
          from your stripe account. All invoices paid are subject to a 5% fee.
        </p>
        <br />
        <div style={{ display: 'flex', flexDirection: 'row', alignItems: 'baseling' }}>
          <input
            type="checkbox"
            name="terms"
            id="terms"
            onChange={() => this.setState({ terms: !this.state.terms })}
          />
          <h4 style={{ marginTop: 0, marginLeft: 5, maxWidth: 250 }}>
            By checking this box, you agree to payMe taking a 5% fee off all invoices paid.
            ($1,000.00 invoice = $50.00 fee + $950.00 deposited into your stripe account.
          </h4>
        </div>
        <br />
        <a
          style={{ display: this.state.terms ? null : 'none' }}
          href={`/stripe/authorize?jwt=${localStorage.getItem('id')}`}
        >
          <button>Connect Stripe</button>
        </a>
      </div>
    );
  }
}