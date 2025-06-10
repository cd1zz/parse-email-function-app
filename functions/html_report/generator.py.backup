import logging
from jinja2 import Template
from urllib.parse import unquote
import azure.functions as func

logger = logging.getLogger(__name__)

CATEGORY_STYLES = {
    "PHISHING": "background-color: #d9534f; color: white; padding: 5px 10px; text-transform: uppercase;",
    "JUNK/SPAM": "background-color: #f0ad4e; color: white; padding: 5px 10px; text-transform: uppercase;",
    "LEGITIMATE": "background-color: #5cb85c; color: white; padding: 5px 10px; text-transform: uppercase;",
    "SUSPICIOUS": "background-color: #f0ad4e; color: white; padding: 5px 10px; text-transform: uppercase;",
    "DEFAULT": "background-color: #cccccc; color: white; padding: 5px 10px; text-transform: uppercase;"
}

def create_html(json_data):
    html_template = '''
    <html>
    <head>
        <style>
            body {
                font-family: Aptos, sans-serif;
                line-height: 1.6;
                background-color: #f9f9f9;
                color: #333;
                margin: 20px;
            }
            h2 {
                color: #4CAF50;
                border-bottom: 2px solid #4CAF50;
                padding-bottom: 5px;
            }
        </style>
    </head>
    <body>
        {% set section_order = [
            'final_assessment',
            'email_summary',
            'pretense_vs_intent_mapping',
            'intent_verification',
            'logical_coherence',
            'behavioral_triggers',
            'url_analysis',
            'attachment_analysis',
            'contextual_integrity',
            'subtle_clue_detection',
            'domain_reputation_analysis',
            'financial_pretext_detection',
            'bec_reconnaissance_detection'
        ] %}
        {% for section in section_order %}
            {% if section in json_data %}
                <div class="section">
                    <h2>{{ section.replace('_', ' ').title() }}</h2>
                    
                    {% if 'description' in json_data[section] %}
                        <p><em>{{ json_data[section]['description'] }}</em></p>
                    {% endif %}
                    
                    {% if section == 'final_assessment' %}
                        <p>
                            <strong>Category:</strong>
                            <span style="{{ category_styles.get(json_data[section]['category']|upper, category_styles['DEFAULT']) }}">
                                {{ json_data[section]['category']|upper if json_data[section]['category'] else 'N/A' }}
                            </span>
                        </p>
                        <p><strong>Rationale:</strong> {{ json_data[section]['rationale'] if json_data[section]['rationale'] else 'N/A' }}</p>
                    
                    {% elif section == 'attachment_analysis' %} 
                        {% for key, value in json_data[section].items() %}
                            {% if key == "attachment_metadata" %}
                                <h3>Attachment Metadata</h3>
                                <ul>
                                    {% for meta_key, meta_value in value.items() %}
                                        {% if meta_value is mapping %}
                                            <li><strong>{{ meta_key.replace('_', ' ').title() }}:</strong></li>
                                            <ul>
                                                {% for sub_meta_key, sub_meta_value in meta_value.items() %}
                                                    <li><strong>{{ sub_meta_key.replace('_', ' ').title() }}:</strong> {{ sub_meta_value if sub_meta_value else 'N/A' }}</li>
                                                {% endfor %}
                                            </ul>
                                        {% else %}
                                            <li><strong>{{ meta_key.replace('_', ' ').title() }}:</strong> {{ meta_value if meta_value else 'N/A' }}</li>
                                        {% endif %}
                                    {% endfor %}
                                </ul>
                            {% elif key == "risks" %}
                                <h3>Attachment Risks</h3>
                                <p>{{ value if value else 'N/A' }}</p>
                            {% endif %}
                        {% endfor %}
                    {% else %}
                        {% for subkey, subvalue in json_data[section].items() %}
                            {% if subkey != 'description' %}
                                {% if subvalue is mapping %}
                                    <h3>{{ subkey.replace('_', ' ').title() }}</h3>
                                    <ul>
                                        {% for key, value in subvalue.items() %}
                                            {% if value is iterable and not value is string %}
                                                <li>
                                                    <strong>{{ key.replace('_', ' ').title() }}:</strong>
                                                    <ul>
                                                        {% if value|length > 0 %}
                                                            {% for item in value %}
                                                                <li class="styled-list-item">{{ item }}</li>
                                                            {% endfor %}
                                                        {% else %}
                                                            <li class="styled-list-item">N/A</li>
                                                        {% endif %}
                                                    </ul>
                                                </li>
                                            {% else %}
                                                <li>
                                                    <strong>{{ key.replace('_', ' ').title() }}:</strong> 
                                                    {{ value if value else 'N/A' }}
                                                </li>
                                            {% endif %}
                                        {% endfor %}
                                    </ul>
                                {% elif subvalue is iterable and not subvalue is string %}
                                    <h3><strong>{{ subkey.replace('_', ' ').title() }}:</strong></h3>
                                    <ul>
                                        {% if subvalue|length > 0 %}
                                            {% for item in subvalue %}
                                            <li class="styled-list-item">{{ item }}</li>
                                            {% endfor %}
                                        {% else %}
                                            <li class="styled-list-item">N/A</li>
                                        {% endif %}
                                    </ul>
                                {% else %}
                                    <p><strong>{{ subkey.replace('_', ' ').title() }}:</strong> {{ subvalue if subvalue else 'N/A' }}</p>
                                {% endif %}
                            {% endif %}
                        {% endfor %}
                    {% endif %}
                </div>
            {% endif %}
        {% endfor %}

    </body>
    </html>
    '''
    
    # Render template
    template = Template(html_template)
    return template.render(json_data=json_data, category_styles=CATEGORY_STYLES)


def generate_html_report(req: func.HttpRequest) -> func.HttpResponse:
    logger.info('Processing request to generate phishing HTML report.')

    try:
        # Parse the request body
        req_body = req.get_json()
        logger.info("Request body successfully parsed.")

        # Validate the input is a dict
        if not isinstance(req_body, dict):
            logger.warning("Invalid input format. Expected a JSON object.")
            return func.HttpResponse(
                "Invalid input format. Expected a JSON object.",
                status_code=400
            )

        # Generate HTML Report using the helper function
        html_report = create_html(req_body)
        html_report = unquote(html_report)

        # Return HTML Report as response
        logger.info("Returning generated HTML report.")
        return func.HttpResponse(
            html_report,
            status_code=200,
            mimetype="text/html",
            headers={
                "Content-Type": "text/html; charset=utf-8"
            }
        )

    except ValueError as e:
        logger.error(f"Invalid JSON input: {e}")
        return func.HttpResponse(
            "Invalid JSON input.",
            status_code=400
        )

    except Exception as e:
        logger.error(f"An error occurred: {e}")
        return func.HttpResponse(
            f"An internal error occurred: {e}",
            status_code=500
        )
