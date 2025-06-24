import logging
from jinja2 import Template
from urllib.parse import unquote
import azure.functions as func

logger = logging.getLogger(__name__)

# Generic category styles that can be used for any classification value
CATEGORY_STYLES = {
    "PHISHING": "background-color: #d9534f; color: white; padding: 5px 10px; text-transform: uppercase;",
    "SPAM": "background-color: #f0ad4e; color: white; padding: 5px 10px; text-transform: uppercase;",
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
                margin-top: 25px;
            }
            ul {
                list-style-type: none;
                padding-left: 20px;
            }
            li {
                margin-bottom: 5px;
            }
            .category-tag {
                padding: 5px 10px;
                text-transform: uppercase;
                font-weight: bold;
            }
            .json-key {
                font-weight: bold;
            }
            .json-value {
                font-weight: normal;
            }
        </style>
    </head>
    <body>
        {% macro render_json(data, level=1, indent=0) %}
            {% if data is mapping %}
                {% for key, value in data.items() %}
                    <div style="margin-left: {{ indent * 20 }}px;">
                        <span class="json-key">{{ key | replace('_', ' ') | title }}:</span>
                        
                        {% if key|lower in ['category', 'classification'] and value is string %}
                            <span class="category-tag" style="{{ category_styles.get(value|upper, category_styles['DEFAULT']) }}">
                                {{ value|upper if value else 'N/A' }}
                            </span>
                        {% elif value is mapping %}
                            {{ render_json(value, level + 1, indent + 1) }}
                        {% elif value is iterable and not value is string %}
                            <ul>
                                {% if value|length > 0 %}
                                    {% for item in value %}
                                        <li>
                                            {% if item is mapping or (item is iterable and not item is string) %}
                                                {{ render_json(item, level + 1, indent + 1) }}
                                            {% else %}
                                                <span class="json-value">{{ item if item else 'N/A' }}</span>
                                            {% endif %}
                                        </li>
                                    {% endfor %}
                                {% else %}
                                    <li><span class="json-value">N/A</span></li>
                                {% endif %}
                            </ul>
                        {% else %}
                            <span class="json-value">{{ value if value else 'N/A' }}</span>
                        {% endif %}
                    </div>
                {% endfor %}
            {% elif data is iterable and not data is string %}
                <ul>
                    {% for item in data %}
                        <li>
                            {% if item is mapping or (item is iterable and not item is string) %}
                                {{ render_json(item, level + 1, indent + 1) }}
                            {% else %}
                                <span class="json-value">{{ item if item else 'N/A' }}</span>
                            {% endif %}
                        </li>
                    {% endfor %}
                </ul>
            {% else %}
                <span class="json-value">{{ data if data else 'N/A' }}</span>
            {% endif %}
        {% endmacro %}
        
        {# Process final_assessment first if it exists #}
        {% if "final_assessment" in json_data %}
            <h2>Final Assessment</h2>
            {{ render_json(json_data["final_assessment"], level=1, indent=0) }}
        {% endif %}

        {# Process all other top-level keys #}
        {% for key, value in json_data.items() %}
            {% if key != "final_assessment" %}
                <h2>{{ key | replace('_', ' ') | title }}</h2>
                {{ render_json(value, level=1, indent=0) }}
            {% endif %}
        {% endfor %}
    </body>
    </html>
    '''
    
    # Render template
    template = Template(html_template)
    return template.render(json_data=json_data, category_styles=CATEGORY_STYLES)


def generate_html_report(req: func.HttpRequest) -> func.HttpResponse:
    logger.info('Processing request to generate HTML report from JSON data.')

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