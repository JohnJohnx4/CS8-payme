import React from 'react';

const View = (props) => {
  return ( 
    <div className="view-invoice-box">
      <div className="view-invoice-details">
      <div className="view-invoice-details-flex">
          <p>Invoice pdf(not working)</p>
          <p>{props.invoice.pdf}</p>
        </div>
        <div className="view-invoice-details-flex">
          <p>Invoice Number:</p>
          <p>{props.invoice.number}</p>
        </div>
        <div className="view-invoice-details-flex">
          <p>Client Name:</p>
          <p>{props.invoice.clientName}</p>
        </div>
        <div className="view-invoice-details-flex">
          <p>Company Name</p>
          <p>{props.invoice.companyName}</p>
        </div>
        <div className="view-invoice-details-flex">
          <p>Total Amount: $</p>
          <p className="view-invoice-details-total">{props.invoice.totalAmount}</p>
        </div>
      </div>
    </div>
   );
}
 
export default View;